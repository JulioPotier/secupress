<?php
defined( 'ABSPATH' ) or die('Cheatin\' uh?');


/**
 * Base scan interface.
 *
 * @package SecuPress
 * @since 1.0
 */

interface iSecuPress_Scan {

	public static function get_messages( $message_id = null );
	public function scan();
	public function fix();

}


/**
 * Base scan abstract class.
 *
 * @package SecuPress
 * @since 1.0
 */

abstract class SecuPress_Scan implements iSecuPress_Scan {

	const VERSION = '1.0';

	protected static $name   = '';
	protected        $result = array();
	protected        $fix    = false;

	public    static $prio  = '';
	public    static $type  = '';
	public    static $title = '';
	public    static $more  = '';


	// Instance ====================================================================================

	/**
	 * Returns the *Singleton* instance of this class.
	 *
	 * @return Singleton The *Singleton* instance.
	 */
	public static function get_instance() {
		if ( ! isset( static::$_instance ) ) {
			static::$_instance = new static;
		}

		return static::$_instance;
	}


	/**
	 * Protected constructor to prevent creating a new instance of the
	 * *Singleton* via the `new` operator from outside of this class.
	 */
	final private function __construct() {
		static::init();
	}


	/**
	 * Private clone method to prevent cloning of the instance of the
	 * *Singleton* instance.
	 *
	 * @return void
	 */
	final private function __clone() {}


	/**
	 * Private unserialize method to prevent unserializing of the *Singleton*
	 * instance.
	 *
	 * @return void
	 */
	final private function __wakeup() {}


	// Properties ==================================================================================

	public static function get_name() {
		return static::$name;
	}


	// Init ========================================================================================

	protected static function init() {
		die( 'Method SecuPress_Scan::init() must be over-ridden in a sub-class.' );
	}


	// Status and messages =========================================================================

	// Maybe set current status.

	public function set_status( $status, $force = false ) {
		$statuses = array(
			'good'    => 0,
			'warning' => 1,
			'bad'     => 2,
		);

		// Unkown status
		if ( ! isset( $statuses[ $status ] ) ) {
			return false;
		}

		// No previous status
		if ( empty( $this->result['status'] ) || $force ) {
			$this->result['status'] = $status;
			return $status;
		}

		// Status already set: only allow to "upgrade" to a superior status.
		if ( $statuses[ $status ] > $statuses[ $this->result['status'] ] ) {
			$this->result['status'] = $status;
		}

		return $this->result['status'];
	}


	// Get messages.

	public static function get_messages( $message_id = null ){
		die( 'Method SecuPress_Scan::get_messages() must be over-ridden in a sub-class.' );
	}


	// Add a message and automatically set the status.

	public function add_message( $message_id, $params = array() ) {
		$this->result['msgs'] = isset( $this->result['msgs'] ) ? $this->result['msgs'] : array();
		$this->result['msgs'][ $message_id ] = $params;

		if ( $message_id < 100 ) {

			$this->set_status( 'good' );

		} elseif  ( $message_id < 200 ) {

			$this->set_status( 'warning' );

		} elseif ( $message_id < 300 ) {

			$this->set_status( 'bad' );

		}
	}


	// Are status and message(s) set?

	public function has_status() {
		return ! empty( $this->result );
	}


	// Set a status + message only if no status is set yet.

	public function maybe_set_status( $message_id, $params = array() ) {
		if ( ! $this->has_status() ) {
			$this->add_message( $message_id, $params );
		}
	}


	// Scan and fix ================================================================================

	// Scan for flow(s).

	public function scan() {
		$this->update();

		return $this->result;
	}


	// Try to fix the flow(s).

	public function fix() {
		if ( ! defined( 'DOING_AJAX' ) ) {
			$this->fix = true;
			return $this->scan();
		}
	}

	// Options =====================================================================================

	// Get options array.

	public static function get() {
		$opts = get_option( SECUPRESS_SCAN_SLUG, array() );
		return is_array( $opts ) ? $opts : array();
	}


	// Set options.

	public function update() {

		if ( $this->fix ) {
			$this->result['attempted_fixes'] = array_key_exists( 'attempted_fixes', $this->result ) ? ++$this->result['attempted_fixes'] : 1;
		}

		$opts = self::get();
		$opts = array_merge( $opts, array( static::$name => $this->result ) );

		if ( ! update_option( SECUPRESS_SCAN_SLUG, $opts ) ) {
			return false;
		}

		return $this->result;
	}


	// Tools =======================================================================================

	// Get prioritie(s).

	public static function get_priorities( $level = null ) {
		$priorities = array(
			'high' => array(
				'title'       => __( 'High Priority', 'secupress' ),
				'description' => __( 'These tests should be fixed now.', 'secupress' ),
			),
			'medium' => array(
				'title'       => __( 'Medium Priority', 'secupress' ),
				'description' => __( 'These tests should be fixed when you can if no conflict are found', 'secupress' ),
			),
			'low' => array(
				'title'       => __( 'Low Priority', 'secupress' ),
				'description' => __( 'These tests should be fixed to improve your security, but not mandatory.', 'secupress' ),
			),
		);

		if ( isset( $level ) ) {
			return isset( $priorities[ $level ] ) ? $priorities[ $level ] : array( 'title' => __( 'Unkown Priority', 'secupress' ), 'description' => '' );
		}

		return $priorities;
	}

	public static function get_tests() {
		return array(
			'high' => array(
				'Versions',         'Auto_Update',       'Bad_Old_Plugins',
				'Bad_Config_Files', 'Directory_listing', 'PHP_INI',
				'Admin_User_Check', 'Easy_Login',        'Subscription',
				'WP_Config',        'Salt_Keys',         'Passwords_Strength',
				'Bad_Old_Files',    'Chmods',            'Common_Flaws',
				'Bad_User_Agent',   'SQLi',
			),
			'medium' => array(
				'Inactive_Plugins_Themes', 'Bad_Url_Access',  'Bad_Usernames',
				'Bad_Request_Methods',     'Too_Many_Admins', 'Block_Long_URL',
				'Block_HTTP_1_0',          'Discloses',
			),
			'low' => array(
				'Login_Errors_Disclose', 'PHP_Disclosure', 'Admin_As_Author'
			),
		);
	}

	// Given an array of "things", wrap those "things" in a HTML tag.

	public static function wrap_in_tag( $array, $tag = 'code' ) {
		$out = array();

		if ( $array ) {
			foreach ( (array) $array as $thing ) {
				$out[] = sprintf( '<%2$s>%1$s</%2$s>', $thing, $tag );
			}
		}

		return $out;
	}

}
