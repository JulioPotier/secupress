<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

return;
$this->set_current_section( 'monitoring' );
$this->set_section_description( sprintf( __( '<strong>WP Umbrella</strong> is the most comprehensive monitoring plugin in the World. This includes: tracking WordPress PHP errors which can prevent poor performance and security risks, monitoring uptime, performance and site health.', 'secupress' ), SECUPRESS_PLUGIN_NAME ) );
$this->add_section( '<span class="dashicons dashicons-admin-plugins"></span> WP Umbrella', array( 'with_save_button' => false ) );
$this->add_field( array(
	'type'                => 'plugin',
	'name'                => 'wp-health',
	'helpers'             => array(
		// 'description' => array(
		// 	'type'        => 'description',
		// 	'description' => __( 'What happened on your website? By activating this add-on, most sensitive actions will be logged.', 'secupress' ),
		// ),
		'help' => array(
			'type'        => 'help',
			'description' => sprintf( __( 'This will install <strong>%s</strong> from the official WordPress repository.', 'secupress' ), 'WP Security Audit Log' ),
		),
	),
) );
