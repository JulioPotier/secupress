<?php
defined( 'ABSPATH' ) or die('Cheatin\' uh?');

/**
 * Base scan class.
 *
 * @package SecuPress
 * @since 1.0
 */

class SecuPress_Scan {

	const VERSION     = '1.0';

	protected static $instance      = false;
	protected static $name          = '';
	protected        $result        = array();
	protected        $fix            = false;

	public    static $prio  = '';
	public    static $type  = '';
	public    static $title = '';
	public    static $more  = '';


	public function __construct( $args = array() ) {}


	public static function get_instance( $args = array() ) {
		if ( ! self::$instance ) {
			$classname = __CLASS__;
			self::$instance = new $classname//;
			( $args );
		}

		return self::$instance;
	}


	public static function get_name() {
		return static::$name;
	}


	public static function get_priorities( $level = null ) {
		$priorities = array(
			'high' => array(
				'title' => __( 'High Priority', 'secupress' ),
				'description' => __( 'These tests should be fixed now.', 'secupress' ),
			),
			'medium' => array(
				'title' => __( 'Medium Priority', 'secupress' ),
				'description' => __( 'These tests should be fixed when you can if no conflict are found', 'secupress' ),
			),
			'low' => array(
				'title' => __( 'Low Priority', 'secupress' ),
				'description' => __( 'These tests should be fixed to improve your security, but not mandatory.', 'secupress' ),
			),
		);

		if ( isset( $level ) ) {
			return isset( $priorities[ $level ] ) ? $priorities[ $level ] : array( 'title' => __( 'Unkown Priority', 'secupress' ), 'description' => '' );
		}

		return $priorities;
	}


	public static function get_messages( $id = null ) {
		die( 'function SecuPress_Scan::get_messages() must be over-ridden in a sub-class.' ); // no i18n thx
	}


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


	// Add a message and automatically set the status.

	public function add_message( $id, $params = array() ) {
		$this->result['msgs'] = isset( $this->result['msgs'] ) ? $this->result['msgs'] : array();
		$this->result['msgs'][ $id ] = $params;

		if ( $id < 100 ) {

			$this->set_status( 'good' );

		} elseif  ( $id < 200 ) {

			$this->set_status( 'warning' );

		} elseif ( $id < 300 ) {

			$this->set_status( 'bad' );

		}
	}


	public function scan() {
		$this->update();

		return $this->result;
	}


	public function fix() {
		$this->fix = true;
		return $this->scan();
	}


	public function update() {

		$opts = get_option( SECUPRESS_SCAN_SLUG, array() );
		$opts = is_array( $opts ) ? $opts : array();

		if ( $this->fix ) {
			$this->result['attempted_fixes'] = array_key_exists( 'attempted_fixes', $this->result ) ? ++$this->result['attempted_fixes'] : 1;
		}

		$opts = array_merge( $opts, array( static::$name => $this->result ) );

		if ( ! update_option( SECUPRESS_SCAN_SLUG, $opts ) ) {
			return false;
		}

		return $this->result;
	}
}
