<?php

namespace devtoolboxuk\google2fa;

class SecretFactory
{
    protected $secretLength;

    /**
     * @param int $secretLength
     */
    public function __construct($secretLength = 16)
    {
        if ($secretLength == 0 || $secretLength % 8 > 0) {
            throw new \InvalidArgumentException("Secret length must be longer than 0 and divisible by 8");
        }
        $this->secretLength = $secretLength;
    }

    /**
     * @param $issuer
     * @param $accountName
     * @return Secret
     * @throws \Exception
     */
    public function create($issuer, $accountName)
    {
        return new Secret($issuer, $accountName, $this->generateSecretKey());
    }

    /**
     * @return string
     * @throws \Exception
     */
    public function generateSecretKey()
    {
        $key = "";
        while (strlen($key) < $this->secretLength) {
            $key .= $this->_getBase32LookupTable();
        }

        return $key;
    }

    /**
     * @return mixed
     * @throws \Exception
     */
    protected function _getBase32LookupTable()
    {
        $base32Chars = [
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', //  7
            'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', // 15
            'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', // 23
            'Y', 'Z', '2', '3', '4', '5', '6', '7', // 31
        ];
        return $base32Chars[random_int(0, 31)];

    }
}
