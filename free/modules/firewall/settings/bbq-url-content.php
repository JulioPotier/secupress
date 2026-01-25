<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );


$this->set_current_section( 'bbq_url_contents' );
$this->add_section( __( 'Malicious URLs', 'secupress' ) );


$main_field_name = $this->get_field_name( 'bad-contents' );

$this->add_field( array(
	'title'             => __( 'Block Bad Content', 'secupress' ),
	'label_for'         => $main_field_name,
	'description'       => __( 'Attackers or scripts may attempt to add malicious parameters to URLs, aiming to exploit vulnerabilities on your website.', 'secupress' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'firewall', 'bad-url-contents' ),
	'label'             => __( 'Yes, protect my site from malicious content in URLs', 'secupress' ),
) );

$this->add_field( array(
	'title'             => __( 'Block 404 requests on PHP files', 'secupress' ),
	'description'       => __( 'Allows you to redirect people who attempt to access hidden or malicious PHP files on a 404 page not found error.', 'secupress' ),
	'label_for'         => $this->get_field_name( 'ban-404-php' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'firewall', 'ban-404-php' ),
	'label'             => __( 'Yes, protect my site from 404 on .php files', 'secupress' ),
) );
