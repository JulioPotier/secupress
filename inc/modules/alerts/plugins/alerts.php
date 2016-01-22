<?php
/*
Module Name: Alerts
Description: Receve alerts on specific events.
Main Module: alerts
Author: SecuPress
Version: 1.0
*/

defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

/*------------------------------------------------------------------------------------------------*/
/* INCLUDE AND INITIATE ========================================================================= */
/*------------------------------------------------------------------------------------------------*/

if ( ! did_action( 'secupress_plugins_loaded' ) ) {

	require_once( SECUPRESS_MODULES_PATH . 'alerts/plugins/inc/php/alerts/class-secupress-alerts.php' );

	SecuPress_Alerts::get_instance();

}
