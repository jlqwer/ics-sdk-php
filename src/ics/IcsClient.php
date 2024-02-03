<?php
namespace Ics;

/**
 * ICS4 PHP SDK v1.3.0
 * @author jlqwer
 * @date 2024-02-03
 */
class IcsClient
{
    private $appid;
    private $appkey;
    private $secretkey;

    /**
     * IcsClient constructor.
     * @param $appid
     * @param $appkey
     * @param $secretkey
     */
    public function __construct($appid, $appkey, $secretkey)
    {
        $this->appid = $appid;
        $this->appkey = $appkey;
        $this->secretkey = $secretkey;
    }

    /**
     * Encrypted data
     * @param $data
     * @return string
     * @author jlqwer
     * @date 2021-05-27
     */
    private function encryptData($data)
    {
        return bin2hex(openssl_encrypt($data, "AES-128-CBC", substr($this->secretkey, 0, 16), 1, substr($this->secretkey, 16, 16)));
    }

    /**
     * Decrypted data
     * @param $data
     * @return false|string
     * @author lixiuguo
     * @date 2021-05-27
     */
    private function decryptData($data)
    {
        $data = hex2bin($data);
        $data = openssl_decrypt($data, "AES-128-CBC", substr($this->secretkey, 0, 16), 1, substr($this->secretkey, 16, 16));
        return json_decode($data, true);
    }

    /**
     * Send Post
     * @param $url
     * @param $post_data
     * @return bool|string
     * @author jlqwer
     * @date 2021-05-27
     */
    private function sendPost($url, $post_data)
    {
        $curl = curl_init();
        curl_setopt($curl, CURLOPT_URL, $url);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($curl, CURLOPT_POST, 1);
        curl_setopt($curl, CURLOPT_POSTFIELDS, $post_data);
        curl_setopt($curl, CURLOPT_USERAGENT, 'Mozilla/5.0 (compatible; Ics/3.4; +https://ics.jlqwer.com/api/about)');
        $output = curl_exec($curl);
        curl_close($curl);
        return json_decode($output, true);
    }
    
    /**
     * Request
     *
     * @param $url
     * @param $data
     * @param bool $encrypt
     *
     * @return bool|string
     * @author jlqwer
     * @date 2021-05-27
     */
    public function request($url, $data, bool $encrypt = true)
    {
        $param = [];
        $param['appid'] = $this->appid;
        $param['ak'] = $this->appkey;
        $param['appkey'] = $this->appkey;
        $data = json_encode($data);
        if ($encrypt) {
            $param['data'] = $this->encryptData($data);
        }
        $param['timestamp'] = time();
        $param['nonce'] = uuid_create(1);
        $param['sign'] = hash('sha256', $param['data'].$param['timestamp'].$param['nonce'].$this->secretkey);
        $result = $this->sendPost($url, $param);
        if (!empty($result['data']) && ctype_xdigit($result['data'])) {
            $result['data'] = $this->decryptData($result['data']);
        }
        return $result;
    }
}

