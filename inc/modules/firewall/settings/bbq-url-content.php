<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'bbq_url_contents' );
$this->add_section( __( 'Malicious URLs', 'secupress' ) );


$main_field_name = $this->get_field_name( 'bad-contents' );

$this->add_field( array(
	'title'             => __( 'Block bad content', 'secupress' ),
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
	'title'             => __( 'Block SQLi Scan Attempts', 'secupress' ),
	'description'       => __( 'Fool SQLi scanner/scripts to always give them different content on each reload of the same page.', 'secupress' ),
	'label_for'         => $this->get_field_name( 'bad-sqli-scan' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'firewall', 'bad-sqli-scan' ),
	'label'             => __( 'Yes, protect my site from SQL injection scanners', 'secupress' ),
	'helpers'           => array(
		array(
			'type'        => 'description',
			'description' => __( 'To determine if a URL is vulnerable to an SQL Injection flaw, automated scanner requires a triple page reload to be identical. By giving them a different content for each request, it will not be possible for it to work properly.', 'secupress' ),
		),
	),
) );


$this->add_field( array(
	'title'             => __( 'Block 404 requests on PHP files', 'secupress' ),
	'description'       => __( 'When someone is tring to find a hidden or malicious PHP file, they could just get a 404 error, page not found. Block them.', 'secupress' ),
	'label_for'         => $this->get_field_name( 'ban-404-php' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'firewall', 'ban-404-php' ),
	'label'             => __( 'Yes, protect my site from 404 on .php files', 'secupress' ),
) );
