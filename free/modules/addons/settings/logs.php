<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );


$this->set_current_section( 'logs' );
$this->set_section_description( __( '<strong>WP Activity Log</strong> is the most comprehensive & easy to use WordPress activity log plugin. Keep an activity log of everything that happens on your WordPress sites and multisite networks with the this plugin.', 'secupress' ) );
$this->add_section( '<span class="dashicons dashicons-admin-plugins"></span> WP Activity Log', array( 'with_save_button' => false ) );
$this->add_field( array(
	'type'                => 'plugin',
	'name'                => 'wp-security-audit-log',
	'helpers'             => array(
		'help' => array(
			'type'        => 'help',
			'description' => sprintf( __( 'This will install <strong>%s</strong> from the official WordPress repository.', 'secupress' ), 'WP Security Audit Log' ),
		),
	),
) );
