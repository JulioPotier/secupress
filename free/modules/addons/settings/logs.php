<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );


$this->set_current_section( 'logs' );
$this->set_section_description( sprintf( __( '<strong>WP Activity Log</strong> is the most comprehensive & easy to use WordPress activity log plugin. Keep an activity log of everything that happens on your WordPress sites and multisite networks with the this plugin.', 'secupress' ), SECUPRESS_PLUGIN_NAME ) );
$this->add_section( '<span class="dashicons dashicons-admin-plugins"></span> WP Activity Log', array( 'with_save_button' => false ) );
$this->add_field( array(
	'type'                => 'plugin',
	'name'                => 'wp-security-audit-log',
	'helpers'             => array(
		// 'description' => array(
		// 	'type'        => 'description',
		// 	'description' => '<span class="dashicons dashicons-star-filled"></span> ' . sprintf( __( 'Need more features for %1$s? <a href="%2$s" class="button button-small button-primary">Get %3$s on Pro Version</a>', 'secupress' ), 'WP Security Audit Log', 'https://www.wpsecurityauditlog.com/premium-features/', '-15%' ),
		// ),
		'help' => array(
			'type'        => 'help',
			'description' => sprintf( __( 'This will install <strong>%s</strong> from the official WordPress repository.', 'secupress' ), 'WP Security Audit Log' ),
		),
	),
) );
