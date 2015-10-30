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
			300 => sprintf( __( 'We cannot fix the <code>php.ini</code> file, you have to contact your hosting provider or do it yourself. Need a little <a href="%s">tutorial video</a>?', 'secupress' ), '#' ), //// #
			//// 301 => __( 'The fix has been applied.', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public static function get_ini_values() {
		$ini_values = array(
			'register_globals'  => false,    'display_errors'      => false,    'expose_php'        => false,
			'allow_url_include' => false,    'safe_mode'           => false,    'open_basedir'      => '!empty',
			'log_errors'        => 1,        'error_log'           => '!empty',
			'post_max_size'     => '<64M',   'upload_max_filezize' => '<64M',   'memory_limit'      => '<1024M',
			'disable_functions' => '!empty', 'auto_append_file'    => false,    'auto_prepend_file' => false,
		);

		return $ini_values;
	}


	public function scan() {
		$ini_values = self::get_ini_values();
		$arg_200 = array();
		$arg_201 = array(
			'<code>On</code>'  => array(),
			'<code>Off</code>' => array(),
		);
		$arg_202 = array();

		foreach ( $ini_values as $name => $compare ) {
			$check = ini_get( $name );

			switch ( $compare ) {
				case '!empty':
					if ( '' == $check ) {
						// 200
						$arg_200[] = '<code>' . $name . '</code>';
					}
					break;
				case 1:
					if ( ! $check ) {
						// 201
						$arg_201['<code>On</code>'][] = '<code>' . $name . '</code>';
					}
					break;
				case false:
					if ( $check ) {
						// 201
						$arg_201['<code>Off</code>'][] = '<code>' . $name . '</code>';
					}
					break;
				default:
					if ( '<' === $compare[0] ) {
						$int   = substr( $compare, 1, strlen( $compare ) - 2 );
						$check = substr( $check, 0, strlen( $check ) - 2 ) <= $int;

						if ( ! $check ) {
							// 202
							$compare = str_replace( array( '<', 'M' ), array( '<code>', 'M</code>' ), $compare );

							if ( ! isset( $arg_202[ $compare ] ) ) {
								$arg_202[ $compare ] = array();
							}

							$arg_202[ $compare ][] = '<code>' . $name . '</code>';
						}
					}
					break;
			}
		}

		if ( $count = count( $arg_200 ) ) {
			// bad
			$this->add_message( 200, array( $count, $arg_200 ) );
		}

		$arg_201 = array_filter( $arg_201 );

		if ( $arg_201 ) {
			// bad
			foreach ( $arg_201 as $value => $names ) {
				$count = count( $names );
				$this->add_message( 201, array( $count, $names, $value ) );
			}
		}

		if ( $arg_202 ) {
			// bad
			foreach ( $arg_202 as $value => $names ) {
				$count = count( $names );
				$this->add_message( 202, array( $count, $names, $value ) );
			}
		}

		// good
		$this->maybe_set_status( 0 );

		return parent::scan();
	}


	public function fix() {
/* // later
		$ini_values = self::get_ini_values();
		$htaccess_rules = '';
		$phpini_rules = '';

		foreach ( $ini_values as $name => $compare ) {
			$check = ini_get( $name );

			switch ( $compare ) {
				case '!empty':
					if ( '' == $check ) {
						if ( 'disable_functions' == $name ) {
							$htaccess_rules .= 'php_value ' . $name . ' disable_functions,exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source' . "\n";
							$phpini_rules .= $name . ' = disable_functions,exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source;' . "\n";
						} elseif ( 'error_log' == $name ) {
							$filename = 'error_log_' . uniqid() . '.log';
							$htaccess_rules .= 'php_value ' . $name . ' ' . ABSPATH . $filename . "\n";
							$phpini_rules .= $name . ' = ' . $filename . ';' . "\n";
						} elseif( 'open_basedir' == $name ) {
							$htaccess_rules .= 'php_value ' . $name . ' ' . ABSPATH . "\n";
							$phpini_rules .= $name . ' = ' . ABSPATH . ';' . "\n";
						}
					}
					break;
				case 1:
					if ( ! $check ) {
						$htaccess_rules .= 'php_value ' . $name . ' = On' . "\n";
						$phpini_rules .= $name . ' = On;' . "\n";
					}
					break;
				case false:
					if ( $check ) {
						$htaccess_rules .= 'php_value ' . $name . ' Off' . "\n";
						$phpini_rules .= $name . ' = Off;' . "\n";
					}
					break;
				default:
					if ( '<' === $compare[0] ) {
						$int   = substr( $compare, 1, strlen( $compare ) - 2 );
						$check = substr( $check, 0, strlen( $check ) - 1 );

						if ( $check > $int ) {
							$htaccess_rules .= 'php_value ' . $name . ' ' . $int . 'M' . "\n";
							$phpini_rules .= $name . ' = ' . $int . 'M;' . "\n";
						}

					}
					break;
			}
		}
		secupress_write_htaccess( 'php.ini', $htaccess_rules );
		secupress_put_contents( ABSPATH . 'php.ini', $phpini_rules, array( 'marker' =>  'php.ini' ) );
*/
		$this->add_fix_message( 300 );

		return parent::fix();
	}
}
