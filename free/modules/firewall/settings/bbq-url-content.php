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

$this->add_field( array(
	'title'             => __( 'Block requests that contains PHP function names', 'secupress' ),
	'description'       => __( 'When a PHP function is encountered in a request parameter.', 'secupress' ),
	'label_for'         => $this->get_field_name( 'block-functions' ),
	'plugin_activation' => secupress_is_pro(),
	'disabled'          => ! secupress_is_pro(),
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'firewall', 'block-functions' ),
	'label'             => __( 'Yes, protect my site from function names in requests', 'secupress' ),
	'helpers'      => array(
		array(
			'type'        => secupress_is_pro() ? 'warning' : '',
			'description' => sprintf( __( 'This module is still in %1$s. If you encounter too many blockages, please contact us at %2$s.', 'secupress' ), '<strong>BETA DEV</strong>', secupress_a_me( 'support@secupress.me' ) ),
		),
	),
) );

$this->add_field( array(
	'title'             => __( 'Select sources', 'secupress' ),
	'label_for'         => $this->get_field_name( 'block-functions-sources' ),
	'depends'           => $this->get_field_name( 'block-functions' ),
	'type'              => 'checkboxes',
	'default'           => 'COOKIE',
	'options'           => [ 'COOKIE' => '<code>$_COOKIE</code>', 'POST' => '<code>$_POST</code>', 'GET' => '<code>$_GET</code>' ], // DO NOT TRANSLATE.
	'helpers'      => array(
		array(
			'type'        => 'description',
			'description' => __( 'COOKIE is most commonly used by malwares, followed by POST with possible false positives, and then GET with even more false positives.', 'secupress' ),
		),
		array(
			'type'        => 'warning',
			'class'       => 'hide-if-js',
			'description' => __( 'Select 1 option minimum', 'secupress' ),
		),
	),
) );
