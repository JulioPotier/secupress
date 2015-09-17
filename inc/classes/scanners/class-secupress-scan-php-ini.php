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
	public    static $prio = 'high';


	protected static function init() {
		self::$type  = 'WordPress';
		self::$title = __( 'Check your <code>php.ini</code> configuration.', 'secupress' );
		self::$more  = sprintf(
			__( 'The <code>php.ini</code> file contains many settings. Some of them can easily help you to secure your website. Don\'t let the default configuration running in a production environment. %s.', 'secupress' ),
			'<a href="' . esc_attr__( 'http://doc.secupress.fr/php-ini', 'secupress' ) . '" target="_blank" title="' . esc_attr__( 'Will open a new window', 'secupress' ) . '">' . __( 'Read more about <code>php.ini</code> settings.', 'secupress' ) . '<span class="dashicons dashicons-external" aria-hidden="true"></span></a>'
		);
	}


	public static function get_messages( $message_id = null ) {
		$messages = array(
			// good
			0   => __( 'Your <code>php.ini</code> file is correct.', 'secupress' ),
			// bad
			200 => _n_noop( '%s should not be empty.', '%s should not be empty.', 'secupress' ),
			201 => _n_noop( '%1$s should be set on %2$s.', '%1$s should be set on %2$s.', 'secupress' ),
			202 => _n_noop( '%1$s should be less than %2$s.', '%1$s should be less than %2$s.', 'secupress' ),
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
			'disable_functions' => '!empty', 'auto_append_file'    => false,    'auto_prepend_file' => false,
		);
		$zoo = array();
		$zol = array(
			'<code>On</code>'  => array(),
			'<code>Off</code>' => array(),
		);
		$zoz = array();

		foreach( $ini_values as $name => $compare ) {
			$check = ini_get( $name );

			switch( $compare ) {
				case '!empty':
					if ( '' == $check ) {
						// 200
						$zoo[] = '<code>' . $name . '</code>';
					}
					break;
				case 1:
					if ( ! $check ) {
						// 201
						$zol['<code>On</code>'][] = '<code>' . $name . '</code>';
					}
					break;
				case false:
					if ( $check ) {
						// 201
						$zol['<code>Off</code>'][] = '<code>' . $name . '</code>';
					}
					break;
				default:
					if ( '<' === $compare[0] ) {
						$int   = substr( $compare, 1, strlen( $compare ) - 2 );
						$check = substr( $check, 0, strlen( $check ) - 2 ) <= $int;

						if ( ! $check ) {
							// 202
							$compare = str_replace( array( '<', 'M' ), array( '<code>', 'M</code>' ), $compare );

							if ( ! isset( $zoz[ $compare ] ) ) {
								$zoz[ $compare ] = array();
							}

							$zoz[ $compare ][] = '<code>' . $name . '</code>';
						}
					}
					break;
			}
		}

		if ( $count = count( $zoo ) ) {
			// bad
			$this->add_message( 200, array( $count, wp_sprintf_l( '%l', $zoo ) ) );
		}

		$zol = array_filter( $zol );

		if ( $zol ) {
			// bad
			foreach ( $zol as $value => $names ) {
				$count = count( $names );
				$this->add_message( 201, array( $count, wp_sprintf_l( '%l', $names ), $value ) );
			}
		}

		if ( $zoz ) {
			// bad
			foreach ( $zoz as $value => $names ) {
				$count = count( $names );
				$this->add_message( 202, array( $count, wp_sprintf_l( '%l', $names ), $value ) );
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
