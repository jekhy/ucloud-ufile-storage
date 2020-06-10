<?php

namespace Jekhy\UcloudUfileStorage;

use GuzzleHttp\Client;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Handler\CurlHandler;
use Exception;

class UfileSdkException extends Exception
{
}

class UfileSdk
{
    protected $httpClient;
    protected $bucket;
    protected $pub_key;
    protected $sec_key;
    protected $host;

    protected static function auth($bucket, $pub_key, $sec_key)
    {
        return function (callable $handler) use ($bucket, $pub_key, $sec_key) {
            return function (
                $request,
                array $options
            ) use ($handler, $bucket, $pub_key, $sec_key) {
                $path = $request->getUri()->getPath();
                $method = strtoupper($request->getMethod());
                $paramToSign['method'] = $method;
                foreach (['Content-MD5', 'Content-Type', 'Date'] as $headNeedSign) {
                    $v = $request->getHeader($headNeedSign);
                    $paramToSign[$headNeedSign] = empty($v) ? "" : $v[0];
                }
                $authString = implode("\n", $paramToSign) . "\n";
                // 合并UCloud特殊头
                $headers = $request->getHeaders();
                // 标准化CanonicalizedUCloudHeaders
                foreach ($headers as $k => $v) {
                    $k = strtolower($k);
                    if (strncasecmp($k, "x-ucloud-", strlen('x-ucloud-')) !== 0) {
                        continue;
                    }
                    if (is_array($v)) {
                        $v = implode(',', $v);
                    }
                    $authString .= $k . ":" . trim($v, " ") . "\n";
                }
                // 合并资源路径
                $authString .= "/" . $bucket . $path;
                $signature = base64_encode(hash_hmac('sha1', $authString, $sec_key, true));
                $authToken = "UCloud " . $pub_key . ":" . $signature;
                $request = $request->withHeader('Authorization', $authToken);
                if (in_array($method, ['POST', 'PUT'])) {
                    $request = $request->withHeader('Content-Length', $request->getBody()->getSize());
                }
                return $handler($request, $options);
            };
        };
    }

    public function __construct($bucket, $pub_key, $sec_key, $suffix = '.ufile.ucloud.cn', $https = false, $debug = false)
    {
        $this->bucket = $bucket;
        $this->pub_key = $pub_key;
        $this->sec_key = $sec_key;
        $this->host = ($https ? 'https://' : 'http://') . $bucket . $suffix;
        $stack = new HandlerStack();
        $stack->setHandler(new CurlHandler());
        $stack->push(static::auth($bucket, $pub_key, $sec_key));
        $this->httpClient = new Client(['base_uri' => $this->host, 'handler' => $stack, 'debug' => $debug]);
    }

    public function put($key_name, $contents, $headers = array())
    {
        $resp = $this->httpClient->put($key_name, [
            'headers' => $headers,
            'body' => $contents
        ]);
        return [$resp->getBody()->getContents(), $resp->getStatusCode()];
    }

    public function putFile($key_name, $filePath, $headers = array())
    {
        $resp = $this->httpClient->put($key_name, [
            'headers' => $headers,
            'body' => fopen($filePath, 'r')
        ]);
        return [$resp->getBody()->getContents(), $resp->getStatusCode()];
    }

    public function get($key_name)
    {
        $resp = $this->httpClient->get($key_name);
        if ($resp->getStatusCode() != 200) {
            throw new UfileSdkException("get $key_name error :" . $resp->getStatusCode());
        }
        return $resp->getBody()->getContents();
    }

    public function exists($key_name)
    {
        $resp = $this->httpClient->head($key_name);
        return $resp->getStatusCode() == 200;
    }

    public function size($key_name)
    {
        $resp = $this->httpClient->head($key_name);
        if ($resp->getStatusCode() != 200) {
            throw new UfileSdkException("size $key_name error :" . $resp->getStatusCode());
        }
        return (int)$resp->getHeader('Content-Length')[0];
    }

    public function mime($key_name)
    {
        $resp = $this->httpClient->head($key_name);
        if ($resp->getStatusCode() != 200) {
            throw new UfileSdkException("size $key_name error :" . $resp->getStatusCode());
        }
        return $resp->getHeader('Content-Type')[0];
    }

    public function delete($key_name)
    {
        $resp = $this->httpClient->delete($key_name);
        $httpCode = $resp->getStatusCode();
        if ($httpCode < 200 || $httpCode > 299) {
            throw new UfileSdkException("delete $key_name error :" . $resp->getStatusCode());
        }
        return true;
    }

    public function meta($key_name)
    {
        $resp = $this->httpClient->head($key_name);
        if ($resp->getStatusCode() != 200) {
            throw new UfileSdkException("size $key_name error :" . $resp->getStatusCode());
        }
        $meta = [];
        foreach ($resp->getHeaders() as $k => $v) {
            $meta[$k] = $v[0];
        }
        return $meta;
    }

    public function list($prefix = null, $marker = null, $limit = null)
    {
        $uri = '/?list';
        if ($prefix) {
            $uri .= '&prefix=' . $prefix;
        }
        if ($marker) {
            $uri .= '&marker=' . $marker;
        }
        if ($limit) {
            $uri .= '&limit=' . $limit;
        }
        $resp = $this->httpClient->get($uri);
        return [$resp->getBody()->getContents(), $resp->getStatusCode()];
    }

    /**
     * 初始化分片
     *
     * @param string $key_name
     * @param array  $headers
     * @return array [responseStr, httpCode]
     */
    public function initParts($key_name, $headers = array())
    {
        // https://docs.ucloud.cn/api/ufile-api/initiate_multipart_upload
        $resp = $this->httpClient->post($key_name . '?uploads', [
            'headers' => $headers,
        ]);
        return [$resp->getBody()->getContents(), $resp->getStatusCode()];
    }

    public function uploadPart($key_name, $uploadId, $partNumber, $contents, $headers = array())
    {
        // https://docs.ucloud.cn/api/ufile-api/upload_part
        $headers['Content-Type'] = 'application/octet-stream';
        $headers['Content-Length'] = strlen($contents);
        $resp = $this->httpClient->post($key_name . '?upoloadId=' . $uploadId . '&partNumber=' . $partNumber, [
            'headers' => $headers,
            'body' => $contents
        ]);
        return [$resp->getBody()->getContents(), $resp->getStatusCode()];
    }

    public function finishParts($key_name, $uploadId, $newKey, $contents = '', $headers = array())
    {
        // https://docs.ucloud.cn/api/ufile-api/finish_multipart_upload
        $headers['Content-Length'] = strlen($contents);
        $resp = $this->httpClient->post($key_name . '?upoloadId=' . $uploadId . '&newKey=' . $newKey, [
            'headers' => $headers,
            'body' => $contents
        ]);
        return [$resp->getBody()->getContents(), $resp->getStatusCode()];
    }

    public function deleteParts($key_name, $uploadId)
    {
        // https://docs.ucloud.cn/api/ufile-api/abort_multipart_upload
        $resp = $this->httpClient->delete($key_name . '?upoloadId=' . $uploadId);
        return [$resp->getBody()->getContents(), $resp->getStatusCode()];
    }

    public function getParts($uploadId)
    {
        // https://docs.ucloud.cn/api/ufile-api/get_multi_upload_part
        $resp = $this->httpClient->get('/?muploadpart&uploadId=' . $uploadId);
        return [$resp->getBody()->getContents(), $resp->getStatusCode()];
    }

    public function getAllPatrs($prefix = null, $marker = null, $limit = null)
    {
        // https://docs.ucloud.cn/api/ufile-api/get_multi_upload_id
        $uri = '/?muploadid';
        if ($prefix) {
            $uri .= '&prefix=' . $prefix;
        }
        if ($marker) {
            $uri .= '&marker=' . $marker;
        }
        if ($limit) {
            $uri .= '&limit=' . $limit;
        }
        $resp = $this->httpClient->get($uri);
        return [$resp->getBody()->getContents(), $resp->getStatusCode()];
    }

}
