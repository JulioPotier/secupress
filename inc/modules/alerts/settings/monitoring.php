<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'uptime-monitoring' );
$this->add_section( __( 'Uptime Monitoring', 'secupress' ) );


$consumer_email = sanitize_email( secupress_get_option( 'consumer_email' ) );

$this->add_field( array(
	'title'             => __( 'Monitor my website', 'secupress' ),
	'description'       => sprintf(
		__( 'This tool will alert you when your site is down. Every %s minutes our robot check your website. If it\'s down, you will be immediately notified. Once back, you will be notified to.', 'secupress' ),
		'<strong>' . ( secupress_is_pro() ? '5' : '60' ) . '</strong>'
	),
	'label_for'         => $this->get_field_name( 'activated' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'alerts', 'uptime-monitoring' ),
	'label'             => __( 'Yes, monitor the uptime of my website and alert me if needed', 'secupress' ),
	'disabled'          => empty( $consumer_email ),
	'helpers'           => array(
		array(
			'type'        => 'help',
			'description' => secupress_is_pro() ? '' : __( 'Pro version will check the uptime each <strong>5</strong> minutes instead of 60.', 'secupress' ),
		),
		array(
			'type'        => 'warning',
			'description' => $consumer_email ? sprintf( __( 'The following email address will be used: %s', 'secupress' ), '<code>' . $consumer_email . '</code>' ) : __( 'You need a free API Key to use this module. <a href="#" class="button">Get one!</a>', 'secupress' ),////
		),
		array(
			'type'        => 'warning',
			'description' => secupress_get_deactivate_plugin_string( 'wp-website-monitoring/wordpress-website-monitoring.php' ),
		),
	),
) );
