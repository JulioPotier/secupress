<?php
defined( 'ABSPATH' ) or die( 'Cheatin\' uh?' );


/**
 * 404 Log class.
 *
 * @package SecuPress
 * @since 1.0
 */

class SecuPress_404_Log {

	const VERSION = '1.0';
	/**
	 * @var (string) IP that triggered the 404.
	 */
	protected $user    = '';
	/**
	 * @var (string) A timestamp followed with a #. See `SecuPress_404_Logs::_log()`.
	 */
	protected $time    = 0;
	/**
	 * @var (array)  The log data: basically what will be used in `vsprintf()` (URI, `$_GET`, `$_POST`).
	 */
	protected $data    = array();
	/**
	 * @var (string) The log message.
	 */
	protected $message = '';


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

		$this->_set_message();
	}


	// Public methods ==============================================================================

	/**
	 * Get the log formated date based on its timestamp.
	 *
	 * @since 1.0
	 *
	 * @param (string) $format See http://de2.php.net/manual/en/function.date.php
	 *
	 * @return (string|int) The formated date if a format is provided, the timestamp integer otherwise.
	 */
	public function get_time( $format = 'Y-m-d H:i:s' ) {
		static $gmt_offset;
		if ( ! isset( $gmt_offset ) ) {
			$gmt_offset = get_option( 'gmt_offset' ) * HOUR_IN_SECONDS;
		}
		$timestamp = (int) substr( $this->time, 0, strpos( $this->time, '#' ) );
		return $format ? date_i18n( $format, $timestamp + $gmt_offset ) : $timestamp;
	}


	/**
	 * Get the log user.
	 *
	 * @since 1.0
	 *
	 * @return (string) An IP address.
	 */
	public function get_user() {
		return esc_html( $this->user );
	}


	/**
	 * Get the log message.
	 *
	 * @since 1.0
	 *
	 * @return (string) A message containing all the related data.
	 */
	public function get_message() {
		return $this->message;
	}


	// Private methods =============================================================================

	// Message =====================================================================================

	/**
	 * Set the log message.
	 *
	 * @since 1.0
	 */
	protected function _set_message() {

		$this->message = array();
		$props = array(
			'uri'  => 'URI',
			'get'  => '$_GET',
			'post' => '$_POST',
		);

		foreach ( $this->data as $key => $data ) {
			if ( is_null( $data ) ) {
				$this->data[ $key ] = '<em>[null]</em>';
			} elseif ( true === $data ) {
				$this->data[ $key ] = '<em>[true]</em>';
			} elseif ( false === $data ) {
				$this->data[ $key ] = '<em>[false]</em>';
			} elseif ( '' === $data ) {
				$this->data[ $key ] = '<em>[' . __( 'empty string', 'secupress' ) . ']</em>';
			} elseif ( is_scalar( $data ) ) {
				$count = substr_count( $data, "\n" );

				// 46 seems to be a good limit for the logs module width.
				if ( $count || strlen( $data ) >= 46 ) {
					$this->data[ $key ] = '<pre' . ( $count > 4 ? ' class="secupress-code-chunk"' : '' ) . '>' . esc_html( $data ) . '</pre>';
				} else {
					$this->data[ $key ] = '<code>' . esc_html( $data ) . '</code>';
				}
			} else {
				$data  = print_r( $data, true );
				$count = substr_count( $data, "\n" );
				$this->data[ $key ] = '<pre' . ( $count > 4 ? ' class="secupress-code-chunk"' : '' ) . '>' . esc_html( $data ) . '</pre>';
			}

			$this->message[] = sprintf( __( '%s: ', 'secupress' ), '<code>' . $props[ $key ] . '</code>' ) . $this->data[ $key ];
		}

		$this->message = implode( '<br/>', $this->message );
	}

}
