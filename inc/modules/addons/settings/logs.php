<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'logs' );

$this->add_section( __( 'Logs Add-on', 'secupress' ), array( 'with_save_button' => false ) );
$this->add_field( array(
	'type'                => 'plugin',
	'name'                => 'wp-security-audit-log',
	'helpers'             => array(
		'description' => array(
			'type'        => 'description',
			'description' => __( 'What happened on your website? By activating this add-on, most sensitive actions will be logged.', 'secupress' ),
		),
		'help' => array(
			'type'        => 'help',
			'description' => sprintf( __( 'This will install <strong>%s</strong> from the official WordPress repository.<br><a href="">Learn more about this add-on</a>.', 'secupress' ), 'WP Security Audit Log' ),
		),
	),
) );
