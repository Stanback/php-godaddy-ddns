<?php
/*
 * Command Line Interface (CLI) Client
 *
 * Author: Brian Stanback <stanback@gmail.com>
 * License: New BSD License
 * Website: http://www.stanback.net/code/godaddy-dyndns.html
 * Version: 0.0.6-experimental
 * Last Updated: 4/17/2012
 * Requires: PHP 5.3+, cURL
 *
 * This script was written as a proof-of-concept and is completely unsupported by its
 * author and unaffiliated with GoDaddy(r) and GoDaddy(r) partners or subsidiaries.
 */

/********************************************************************************
 * Copyright (c) 2010-12, Brian Stanback <stanback@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the name of the organization nor the
 *      names of its contributors may be used to endorse or promote products
 *      derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *******************************************************************************/

/*
 * This is a command line interface (CLI) program for updating zone records.
 */

$config = array(
    'service'            => 'GoDaddy',
    'username'           => '',
    'password'           => '',
    'hostname'           => '',
    'myip'               => '',
    'offline'            => false,
    'offline_ip'         => '127.0.0.1',
    'detect_external_ip' => false,
);

// Require and instantiate the required class
$className = $config['service'] . 'DNSZone';
require_once($className . '.class.php');
$zone = new $className($config);
if (!($zone instanceOf $className)) {
    die('Could not load class for service: ' . $config['service']);
}

// Get the command line options
$options = getopt('u::p::m::oh:');

// Get request values, falling back to the defaults above
$username = isset($options['u']) ? $options['u'] : $config['username'];
$password = isset($options['p']) ? $options['p'] : $config['password'];
$hostname = isset($options['h']) ? $options['h'] : $config['hostname'];
$myip     = isset($options['m']) ? $options['m'] : $config['myip'];
$offline  = isset($options['o']) ? true : $config['offline'];

if ($hostname) {
    if ($username && $password) {
        // Authenticate the user
        if ($zone->authenticate($username, $password, $hostname)) {
            if ($offline) {
                // Use offline IP
                $myip = $config['offline_ip'];
            } elseif ($config['detect_external_ip'] && $zone->isPrivateIp($myip)) {
                if (($externalip = $zone->getPublicIp($myip))) {
                    // Use detected external IP
                    $myip = $externalip;
                }
            }

            // Attempt to update the hostname's A record
            if (($result = $zone->setRecord($hostname, $myip, 'A'))) {
                echo (($result['last_ip'] == $result['new_ip']) ? 'No change: ' : 'Change successful: ') . ' ' . $result['new_ip'] . "\n";
            } else {
                echo "An error occurred while setting a host record\n";
            }
        } else {
            echo "Incorrect username or password\n";
        }
    } else {
        echo "Username and password not specified\n";
    }
} else {
    // Output usage
    echo "Usage: {$argv[0]} [-u username] [-p password] [-m myip] [-o] -h <hostname>\n";
    exit(1);
}
