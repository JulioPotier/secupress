<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );


$this->set_current_section( 'daily-reporting' );
$this->add_section( __( 'Daily Reports', 'secupress' ) );


$main_field_name = $this->get_field_name( 'activated' );

$args = [
	'title'             => __( 'Summary of important events every day', 'secupress' ),
	'label_for'         => $main_field_name,
	'disabled'          => ! secupress_is_pro(),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'alerts', 'daily-reporting' ),
];

if ( secupress_is_pro() ) {
	if ( ! class_exists( 'SecuPress_Daily_Reporting' ) ) {
		require_once( SECUPRESS_PRO_MODULES_PATH . 'alerts/plugins/inc/php/alerts/class-secupress-alerts.php' );
		require_once( SECUPRESS_PRO_MODULES_PATH . 'alerts/plugins/inc/php/alerts/class-secupress-daily-reporting.php' );
	   	SecuPress_Daily_Reporting::get_instance();
	}
	$time = SecuPress_Daily_Reporting::get_instance()->cron_time() + get_option( 'gmt_offset' ) * HOUR_IN_SECONDS;
	if ( (int) date( 'G:i', $time ) === 0 ) {
		$time = __( 'midnight', 'secupress' );
	} elseif ( (int) date( 'G:i', $time ) === 12 ) {
		$time = __( 'noon', 'secupress' );
	} else {
		$time = date( __( 'g:i a', 'secupress' ), $time );
	}

	$args['label'] = sprintf( __( 'Yes, send me a daily report at %s.', 'secupress' ), "<strong>$time</strong>" );
} else {
	$args['label'] = __( 'Yes, send me a daily report.', 'secupress' );
}

$this->add_field( $args );
