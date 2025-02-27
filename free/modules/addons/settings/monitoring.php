<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

$this->set_current_section( 'monitoring' );
$plugin_name = 'WP Umbrella';
$this->set_section_description( sprintf( __( '<strong>%s</strong> empowers agencies and WordPress developers to master WordPress maintenance and effortlessly manage multiple sites. It provides everything needed to efficiently manage, monitor, and backup hundreds of WordPress sites.', 'secupress' ), $plugin_name ) );
$this->add_section( '<span class="dashicons dashicons-admin-plugins"></span> WP Umbrella', array( 'with_save_button' => false ) );
$this->add_field( array(
	'type'                => 'plugin',
	'name'                => 'wp-health',
	'helpers'             => array(
		'help' => array(
			'type'        => 'help',
			'description' => sprintf( __( 'This will install <strong>%s</strong> from the official WordPress repository.', 'secupress' ), $plugin_name ),
		),
	),
) );
