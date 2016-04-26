<?php
/*
Module Name: PHP version disclose
Description: Remove the PHP version request header.
Main Module: discloses
Author: SecuPress
Version: 1.0
*/
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );


header_remove( 'X-Powered-By' );
