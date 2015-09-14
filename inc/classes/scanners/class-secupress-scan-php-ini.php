<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * php.ini scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */

class SecuPress_Scan_PHP_INI extends SecuPress_Scan implements iSecuPress_Scan {

	const VERSION = '1.0';

	/**
	 * @var Singleton The reference to *Singleton* instance of this class
	 */
	protected static $_instance;
	protected static $name = 'php_ini';
	public    static $prio = 'high';


	protected static function init() {
		self::$type  = 'WordPress';
		self::$title = __( 'Check your <code>php.ini</code> configuration.', 'secupress' );
		self::$more  = sprintf(
			__( 'The <code>php.ini</code> file contains many settings. Some of them can easily help you to secure your website. Don\'t let the default configuration running in a production environment. %s', 'secupress' ),
			'<a href="' . esc_attr__( 'http://doc.secupress.fr/php-ini', 'secupress' ) . '" target="_blank" title="' . esc_attr__( 'Will open a new window', 'secupress' ) . '">' . __( 'Read more about <code>php.ini</code> settings.', 'secupress' ) . '<span class="dashicons dashicons-external" aria-hidden="true"></span></a>'
		);
	}


	public static function get_messages( $message_id = null ) {
		$messages = array(
			// good
			0   => __( 'The "admin" account is correctly protected.', 'secupress' ),
			// bad
			200 => __( '<code>%s</code> shouldn\'t be empty.', 'secupress' ),
			201 => __( '<code>%1$s</code> should be set on %2$s.', 'secupress' ),
			// cantfix
			300 => __( 'I can not fix this, you have to do it yourself, have fun.', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {
		$ini_values = array(
			'register_globals'  => false,    'display_errors'      => false,    'expose_php'        => false,
			'allow_url_include' => false,    'safe_mode'           => false,    'open_basedir'      => '!empty',
			'log_errors'        => 1,        'error_log'           => '!empty',
			'post_max_size'     => '<64M',   'upload_max_filezize' => '<64M',   'memory_limit'      => '<1024M',
			'disable_functions' => '!empty', 'auto_append_file'    => false,    'auto_prepend_file' => false
		);

		foreach( $ini_values as $name => $compare ) {
			$check = ini_get( $name );

			switch( $compare ) {
				case '!empty':
					if ( '' == $check ) {
						// bad
						$this->add_message( 200, array( $name ) );
					}
					break;
				case 1:
					if ( ! $check ) {
						// bad
						$this->add_message( 201, array( $name, '<code>On</code>' ) );
					}
					break;
				case false:
					if ( $check ) {
						// bad
						$this->add_message( 201, array( $name, '<code>Off</code>' ) );
					}
					break;
				default:
					if ( '<' === $compare[0] ) {
						$int   = substr( $compare, 1, strlen( $compare ) - 2 );
						$check = substr( $check, 0, strlen( $check ) - 2 ) <= $int;

						if ( ! $check ) {
							// bad
							$this->add_message( 201, array( $name, str_replace( array( '<', 'M' ), array( '&lt; <code>', 'M</code>' ), $compare ) ) );	//// Pas sûr que le message d'erreur soit top.
						}
					}
					break;
			}
		}

		// good
		$this->maybe_set_status( 0 );

		return parent::scan();
	}


	public function fix() {

		// include the fix here.

		return parent::fix();
	}
}
