<?php
defined( 'ABSPATH' ) or die('Cheatin\' uh?');

/**
 * Base scan class.
 *
 * @package SecuPress
 * @since 1.0
 */

class SecuPress_Scan {

	const VERSION = '1.0';

	protected static $instance = false;
	protected static $name     = '';
	protected        $result   = array();
	protected        $fix      = false;

	public    static $prio  = '';
	public    static $type  = '';
	public    static $title = '';
	public    static $more  = '';


	// Instance ====================================================================================

	public function __construct( $args = array() ) {}


	public static function get_instance( $args = array() ) {
		if ( ! self::$instance ) {
			$classname = __CLASS__;
			self::$instance = new $classname//;
			( $args );
		}

		return self::$instance;
	}


	// Properties ==================================================================================

	public static function get_name() {
		return static::$name;
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

	public static function get_messages( $message_id = null ) {
		die( 'function SecuPress_Scan::get_messages() must be over-ridden in a sub-class.' ); // no i18n thx
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

	public function maybe_set_status( $message_id = 0, $params = array() ) {
		if ( ! $this->has_status() ) {
			$this->add_message( $message_id, $params );
		}
	}


	// Scan and fix ================================================================================

	// Scan for flow(s).

	public function scan( $fix_attempted = false ) {
		$this->fix = $fix_attempted;

		$this->update();

		return $this->result;
	}


	// Try to fix the flow(s).

	public function fix() {
		return $this->scan( true );
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
