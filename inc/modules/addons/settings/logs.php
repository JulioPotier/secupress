<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'logs' );
$this->set_section_description( sprintf( __( 'Developped by <a href="https://profiles.wordpress.org/wpwhitesecurity">WPWhiteSecurity</a>, <strong>WP Security Audit Log</strong> is a recommended plugin by %s, replacing our old <em>Logs Module</em>. You will easily check what happened on your website, with filters and more.', 'secupress' ), SECUPRESS_PLUGIN_NAME ) );
$this->add_section( '<span class="dashicons dashicons-admin-plugins"></span> WP Security Audit Log', array( 'with_save_button' => false ) );
$this->add_field( array(
	'type'                => 'plugin',
	'name'                => 'wp-security-audit-log',
	'helpers'             => array(
		'description' => array(
			'type'        => 'description',
			'description' => '<span class="dashicons dashicons-star-filled"></span> ' . sprintf( __( 'Need more features for %1$s? <a href="%2$s" class="button button-small button-primary">Get %3$s on Pro Version</a>', 'secupress' ), 'WP Security Audit Log', 'https://www.wpsecurityauditlog.com/premium-features/', '-15%' ),
		),
		'help' => array(
			'type'        => 'help',
			'description' => sprintf( __( 'This will install <strong>%1$s</strong> from the official WordPress repository.', 'secupress' ), 'WP Security Audit Log' ),
		),
	),
) );
