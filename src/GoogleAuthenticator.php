<?php

namespace Camalus\GoogleAuthenticator;

use Base32\Base32;

class GoogleAuthenticator
{
    protected $codeLength = 6;

    /**
     * @param string $secret
     * @param int $code
     * @return bool
     */
    public function authenticate($secret, $code)
    {
        $correct = false;
        for ($i=-1; $i<=1; $i++) {
            if ($this->calculateCode($secret) == $code) {
                $correct = true;
                break;
            }
        }

        return $correct;
    }

    protected function getTimeSlice($offset=0)
    {
        return floor(time() / 30) + ($offset * 30);
    }

    public function calculateCode($secret, $timeSlice=null)
    {
        // If we haven't been fed a timeSlice, then get one.
        $timeSlice = $timeSlice ? $timeSlice : $this->getTimeSlice();

        // Packs the timeslice as a "unsigned long" (always 32 bit, big endian byte order)
        $timeSlice = pack("N", $timeSlice);

        // Then pad it with the null terminator
        $timeSlice = str_pad($timeSlice, 8, chr(0), STR_PAD_LEFT);

        //Google Authenticator uses SHA1
        $hash = hash_hmac("SHA1", $timeSlice, Base32::decode($secret), true);

        // Last 4 bits are an offset apparently
        $offset = ord(substr($hash, -1)) & 0x0F;

        // Grab the last 4 bytes
        $result = substr($hash, $offset, 4);

        // Unpack it again
        $value = unpack('N', $result)[1];

        // Only 32 bits
        $value = $value & 0x7FFFFFFF;

        // Modulo down to the right number of digits
        $modulo = pow(10, $this->codeLength);

        // Finally, pad out the string with 0s
        return str_pad($value % $modulo, $this->codeLength, '0', STR_PAD_LEFT);
    }
}
