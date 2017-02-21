<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'daily-reporting' );
$this->add_section( __( 'Daily Reports', 'secupress' ) );


$main_field_name = $this->get_field_name( 'activated' );

$args = array(
	'title'             => __( 'Send me a summary of important events every day', 'secupress' ),
	'label_for'         => $main_field_name,
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'alerts', 'daily-reporting' ),
	'label'             => __( 'Yes, alert me', 'secupress' ),
);

if ( class_exists( 'SecuPress_Daily_Reporting' ) ) {
	$time = SecuPress_Daily_Reporting::get_instance()->cron_time() + get_option( 'gmt_offset' ) * HOUR_IN_SECONDS;

	if ( (int) date( 'G:i', $time ) === 0 ) {
		$time = __( 'midnight', 'secupress' );
	} elseif ( (int) date( 'G:i', $time ) === 12 ) {
		$time = __( 'noon', 'secupress' );
	} else {
		$time = date( __( 'g:i a', 'secupress' ), $time );
	}

	$args['helpers'] = array(
		array(
			'type'        => 'description',
			/** Translators: %s is a time (hour + minute, or "midnight", or "noon". */
			'description' => sprintf( __( 'A notification will be sent every day at %s.', 'secupress' ), "<strong>$time</strong>" ),
		),
	);
}

$this->add_field( $args );
