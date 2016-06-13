<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'uptime-monitoring' );
$this->add_section( __( 'Uptime Monitoring', 'secupress' ) );


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
	'disabled'          => ! secupress_get_consumer_key(),
	'helpers'           => array(
		array(
			'type'        => 'help',
			'description' => secupress_is_pro() ? '' : sprintf( __( 'Pro version will check the uptime each %1$s minutes instead of %2$s.', 'secupress' ), '<strong>5</strong>', 60 ),
		),
		array(
			'type'        => 'warning',
			'description' => secupress_get_consumer_key() ? '' : sprintf( __( 'You need a free API Key to use this feature. <a href="%s" class="secupress-button secupress-button-primary secupress-button-mini secupress-end button-secupress-get-api-key"><span class="icon"><i class="icon-key" aria-hidden="true"></i></span><span class="text">Get a free key</span></a>', 'secupress' ), esc_url( secupress_admin_url( 'settings' ) ) ),
		),
		array(
			'type'        => 'warning',
			'description' => secupress_get_deactivate_plugin_string( 'wp-website-monitoring/wordpress-website-monitoring.php' ),
		),
	),
) );
