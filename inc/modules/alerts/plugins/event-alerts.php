<?php
/**
 * Module Name: Event Alerts
 * Description: Receive alerts on specific events.
 * Main Module: alerts
 * Author: SecuPress
 * Version: 1.0
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

/*------------------------------------------------------------------------------------------------*/
/* INCLUDE AND INITIATE ========================================================================= */
/*------------------------------------------------------------------------------------------------*/

require_once( SECUPRESS_MODULES_PATH . 'alerts/plugins/inc/php/alerts/class-secupress-alerts.php' );
require_once( SECUPRESS_MODULES_PATH . 'alerts/plugins/inc/php/alerts/class-secupress-event-alerts.php' );

SecuPress_Event_Alerts::get_instance();
