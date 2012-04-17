<?php
/*
 * DNS Zone Interface
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

/**
 * The class which models a DNS zone and defines methods
 * for host records to be added, removed, or updated.
 *
 * @todo This class could be multiple classes: Account, Zone, Record
 */
interface DNSZoneInterface
{
    /**
     * Login to the user's account, returning an error if the credentials are
     * invalid or the login fails.
     *
     * A optional FQDN or TLD can be specified to log the user directly into
     * a specific zone record (eliminates an additional page request).
     */
    public function authenticate($username, $password, $hostname = null);

    /**
     * Check to see if the expected user is logged in.
     */
    public function isLoggedIn($username);

    /**
     * Log the user out.
     */
    public function logout();

    /**
     * Update a host record for the specified FQDN.
     */
    public function setRecord($hostname, $data, $type = 'A');

    /**
     * Uses the hostip.info API to detect and return the remote IP.
     * Useful if this script is running from within a LAN.
     *
     * @todo Move this function elsewhere
     */
    public function getPublicIp();

    /**
     * Checks to see whether an IP address is private (non-routable) or public.
     *
     * @todo Move this function elsewhere
     */
    public function isPrivateIp($ip);
}
