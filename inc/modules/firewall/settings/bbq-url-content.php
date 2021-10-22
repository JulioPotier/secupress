<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );


$this->set_current_section( 'bbq_url_contents' );
$this->add_section( __( 'Malicious URLs', 'secupress' ) );


$main_field_name = $this->get_field_name( 'bad-contents' );

$this->add_field( array(
	'title'             => __( 'Block Bad Content', 'secupress' ),
	'label_for'         => $main_field_name,
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'firewall', 'bad-url-contents' ),
	'label'             => __( 'Yes, protect my site from malicious contents in URLs', 'secupress' ),
	'helpers'           => array(
		array(
			'type'        => 'description',
			'description' => __( 'When accessing your website, attackers or some scripts, scanners will try to add bad params to your URLs to see if a vulnerability could be exploited.', 'secupress' ),
		),
	),
) );


$this->add_field( array(
	'title'        => __( 'Bad Contents List', 'secupress' ),
	'description'  => __( 'Automatically block any request containing any of these keywords automatically.', 'secupress' ),
	'depends'      => $main_field_name,
	'label_for'    => $this->get_field_name( 'bad-contents-list' ),
	'type'         => 'textarea',
	'label'        => __( 'List of bad keywords in requests to block', 'secupress' ),
	'helpers'      => array(
		array(
			'type'        => 'description',
			'description' => __( 'Add or remove keywords you want to be blocked. Keywords are separated by commas.', 'secupress' ),
		),
	),
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
