<?php
namespace XJWT;

use Aws\Kms\KmsClient;

class Token
{

    const TYPE_X_JWT = "X-JWT"; //Json Web Token
    const TYPE_X_JDT = "X-JDT"; //Json Document Token

    public static $types = [
        self::TYPE_X_JWT, self::TYPE_X_JDT
    ];

    /** @var $kmsClient KmsClient */
    private $kmsClient;

    protected $payload = [];
    protected $signature = null;

    public $alg = "AES-256-CBC";
    public $exp = null;
    public $typ = self::TYPE_X_JWT;

    /**
     * Token constructor.
     *
     * @param $kmsConfigs
     */
    function __construct($kmsConfigs = [])
    {
        $defaultKMSConfig = [
            "region" => "us-west-2",
            "version" => "2014-11-01"
        ];
        $config = array_merge_recursive($defaultKMSConfig, $kmsConfigs);
        $this->kmsClient = new KmsClient($config);
    }

    /**
     * Encrypt the data
     *
     * @param $keyId
     * @param bool $withSignature With signature if the token needs to be transport via network. If you directly save the token to db, there is no need for signature.
     * @return string
     */
    public function encrypt($keyId, $withSignature = true)
    {
        /**
         * Headers
         */
        $headers = [];

        if (!in_array($this->alg, openssl_get_cipher_methods())) {
            throw new \InvalidArgumentException("The algorithm is not supported. A list of supported algorithms can be found at: http://php.net/manual/en/function.openssl-get-cipher-methods.php");
        }
        $headers['alg'] = $this->alg;

        if (!in_array($this->typ, self::$types)) {
            throw new \InvalidArgumentException("The type is not supported. ");
        }

        if (!empty($this->exp) && $this->exp > 0) {
            $headers['exp'] = time() + $this->exp;
        }

        $numberOfBytes = openssl_cipher_iv_length($this->alg);
        $iv = openssl_random_pseudo_bytes($numberOfBytes);
        $k = [ 'KeyId' => $keyId, 'NumberOfBytes' => $numberOfBytes ];
        $result = $this->kmsClient->generateDataKey($k);
        $ciphertextBlob = $result->get("CiphertextBlob");

        $headers['iv'] = base64_encode($iv);
        $headers['key'] = base64_encode($ciphertextBlob);

        $encodedHeader = base64_encode(json_encode($headers));

        /**
         * Payload
         */
        $payload = json_encode($this->payload);
        $encryptedPayload = base64_encode(openssl_encrypt($payload, $this->alg, $result->get('Plaintext'), OPENSSL_RAW_DATA, $iv));

        /**
         * Signature
         */
        if ($withSignature === true) {
            $signature = base64_encode(hash_hmac('sha256', $encodedHeader . '.' . $encryptedPayload, $result->get('Plaintext'), true));
            unset($result);

            return implode('.', [ $encodedHeader, $encryptedPayload, $signature ]);
        }

        return implode('.', [ $encodedHeader, $encryptedPayload ]);
    }

    /**
     * Decrypt the token
     *
     * @param $token
     * @param bool $withSignature
     * @return mixed
     */
    public function decrypt($token, $withSignature = true)
    {
        @list($encodedHeader, $encryptedPayload, $signature) = explode('.', $token);

        $headers = json_decode(base64_decode($encodedHeader), true);

        /**
         * Get the secret from aws kms
         */
        $k = [ 'CiphertextBlob' => base64_decode($headers['key']) ];
        $result = $this->kmsClient->decrypt($k);

        /**
         * Validate signature
         */
        if ($withSignature !== false && $signature != base64_encode(hash_hmac('sha256', $encodedHeader . '.' . $encryptedPayload, $result->get('Plaintext'), true))) {
            throw new \InvalidArgumentException("Invalid token. Signature validation failed.");
        }

        /**
         * Check for expiration time.
         */
        if (!empty($headers['exp']) && $headers['exp'] < time()) {
            throw new \InvalidArgumentException("Invalid token. The token has been expired.");
        }

        $decryptedPayload = json_decode(openssl_decrypt(base64_decode($encryptedPayload ), $headers['alg'], $result->get('Plaintext'), OPENSSL_RAW_DATA, base64_decode($headers['iv'])), true);
        $this->setPayload($decryptedPayload);
        if (!empty($headers['exp'])) {
            $this->setExp($headers['exp']);
        }
        $this->setAlg($headers['alg']);

        //destroy the memory hold the plaintext key.
        unset($result);

        return $decryptedPayload;
    }

    /**
     * @return array
     */
    public function getPayload()
    {
        return $this->payload;
    }

    /**
     * @param array $payload
     * @return Token
     */
    public function setPayload($payload)
    {
        $this->payload = $payload;
        return $this;
    }

    /**
     * @return null
     */
    public function getSignature()
    {
        return $this->signature;
    }

    /**
     * @param null $signature
     * @return Token
     */
    public function setSignature($signature)
    {
        $this->signature = $signature;
        return $this;
    }

    /**
     * @return mixed
     */
    public function getAlg()
    {
        return $this->alg;
    }

    /**
     * @param mixed $alg
     * @return $this
     */
    public function setAlg($alg)
    {
        $this->alg = $alg;
        return $this;
    }

    /**
     * @return mixed
     */
    public function getExp()
    {
        return $this->exp;
    }

    /**
     * @param mixed $exp
     * @return $this
     */
    public function setExp($exp)
    {
        $this->exp = $exp;
        return $this;
    }
}