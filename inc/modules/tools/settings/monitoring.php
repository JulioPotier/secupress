<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'uptime-monitoring' );
$this->add_section( __( 'Uptime Monitoring', 'secupress' ) );


$consumer_email = sanitize_email( secupress_get_option( 'consumer_email' ) );

$this->add_field( array(
	'title'             => __( 'Monitor my website', 'secupress' ),
	'description'       => sprintf(
		__( 'This tool will alert you when your site is down. Every %s minutes our robot check this website. If it\'s down, you will be immediately notified by email. Once back, you will be notified to.', 'secupress' ),
		'<strong>' . ( secupress_is_pro() ? '5' : '60' ) . '</strong>'
	),
	'label_for'         => $this->get_field_name( 'activated' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'tools', 'uptime-monitoring' ),
	'label'             => __( 'Yes, monitor the uptime of my website and alert me if needed', 'secupress' ),
	'disabled'          => empty( $consumer_email ),
	'helpers'           => array(
		array(
			'type'        => 'warning',
			'description' => $consumer_email ? sprintf( __( 'The following email address will be used: %s', 'secupress' ), '<code>' . $consumer_email . '</code>' ) : null,
		),
		array(
			'type'        => 'warning',
			'description' => secupress_get_deactivate_plugin_string( 'wp-website-monitoring/wordpress-website-monitoring.php' ),
		),
	),
) );
