<?php
defined( 'ABSPATH' ) or die( 'Cheatin\' uh?' );


/**
 * General Log class.
 *
 * @package SecuPress
 * @since 1.0
 */

class SecuPress_Log {

	const VERSION = '1.0';
	/**
	 * @var (string) A timestamp followed with a #. See `SecuPress_Logs::_get_timestamp()`.
	 */
	protected $time    = 0;
	/**
	 * @var (string) User name + user ID, or an IP address.
	 */
	protected $user    = '';
	/**
	 * @var (array)  The log data: basically what will be used in `vsprintf()`.
	 */
	protected $data    = array();
	/**
	 * @var (string) The log message.
	 */
	protected $message = '';


	// Instance ====================================================================================

	/**
	 * Instenciate the log: must be extended.
	 *
	 * @since 1.0
	 *
	 * @param (string) $time A timestamp followed with a #. See `SecuPress_Logs::_log()`.
	 * @param (array)  $args An array containing at least:
	 *                       - (string) $user User name + user ID, or an IP address.
	 *                       - (array)  $data The log data: basically what will be used in `vsprintf()`.
	 */
	public function __construct( $time, $args ) {}


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
		$gmt_offset = get_option( 'gmt_offset' ) * HOUR_IN_SECONDS;
		$timestamp  = (int) substr( $this->time, 0, strpos( $this->time, '#' ) );
		$timestamp  = $format ? date_i18n( $format, $timestamp + $gmt_offset ) : $timestamp;
		return esc_html( $timestamp );
	}


	/**
	 * Get the log user.
	 *
	 * @since 1.0
	 *
	 * @return (string) User name + user ID, or an IP address.
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

	// Data =====================================================================================

	/**
	 * Set the data.
	 *
	 * @since 1.0
	 *
	 * @param $data (array) The data.
	 */
	protected function _set_data( $data ) {
		$this->data = $data;
	}


	// Message =====================================================================================

	/**
	 * Set the log message.
	 *
	 * @since 1.0
	 */
	protected function _set_message() {
		// Prepare and escape the data.
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
		}

		// Add the data to the message.
		$this->message = vsprintf( $this->message, $this->data );
	}


	// Tools =======================================================================================

	/**
	 * Get a user login followed by his ID.
	 *
	 * @since 1.0
	 *
	 * @param (int|object) A user ID or a WP_User object.
	 *
	 * @return (string) This user login followed by his ID.
	 */
	protected static function _format_user_login( $user ) {
		if ( ! is_object( $user ) ) {
			$user = get_userdata( $user );
		}
		return ( $user ? $user->user_login : '[' . __( 'Unknown user', 'secupress' ) . ']' ) . ' (' . $user->ID . ')';
	}

}
