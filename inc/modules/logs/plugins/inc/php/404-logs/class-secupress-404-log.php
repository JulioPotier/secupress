<?php
defined( 'ABSPATH' ) or die( 'Cheatin\' uh?' );


/**
 * 404s Log class.
 *
 * @package SecuPress
 * @since 1.0
 */

class SecuPress_404_Log extends SecuPress_Log {

	const VERSION = '1.0';


	// Instance ====================================================================================

	/**
	 * Instenciate the log.
	 *
	 * @since 1.0
	 *
	 * @param (string) $time A timestamp followed with a #. See `SecuPress_Logs::_log()`.
	 * @param (array)  $args An array containing:
	 *                       - (array)  $data The log data: basically what will be used in `vsprintf()`.
	 */
	public function __construct( $time, $args ) {
		$args = array_merge( array(
			'user' => '',
			'data' => array(),
		), $args );

		$def_data = array(
			'uri'  => '',
			'get'  => array(),
			'post' => array(),
		);

		$this->time = $time;
		$this->user = $args['user'];
		$this->data = $args['data'];
		$this->data = array_merge( $def_data, $this->data );
		$this->data = array_intersect_key( $this->data, $def_data );

		$this->message  = sprintf( __( '%s: ', 'secupress' ), '<code>URI</code>' ) . '%1$s<br/>';
		$this->message .= sprintf( __( '%s: ', 'secupress' ), '<code>$_GET</code>' ) . '%2$s<br/>';
		$this->message .= sprintf( __( '%s: ', 'secupress' ), '<code>$_POST</code>' ) . '%3$s';

		parent::_set_message();
	}

}
