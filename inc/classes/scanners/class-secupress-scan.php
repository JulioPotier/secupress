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

	// Filled when fixes need manual actions.
	private       $fix_actions = array();

	// The part of the class that extends this one, like SecuPress_Scan_{$class_name_part}.
	protected     $class_name_part;
	// Contain scan results.
	protected     $result     = array();
	// Contain fix results.
	protected     $result_fix = array();

	public static $prio    = '';
	public static $type    = '';
	public static $title   = '';
	public static $more    = '';
	public static $fixable = true;


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
		$this->class_name_part = substr( get_called_class(), 15 ); // 15 is 'SecuPress_Scan_' length.
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


	// Init ========================================================================================

	protected static function init() {
		die( 'Method SecuPress_Scan::init() must be over-ridden in a sub-class.' );
	}


	// Messages for scans and fixes ================================================================

	// Get messages.

	public static function get_messages( $message_id = null ){
		die( 'Method SecuPress_Scan::get_messages() must be over-ridden in a sub-class.' );
	}


	// Status and messages for scans ===============================================================

	// Maybe set current status.

	public function set_status( $status, $force = false ) {
		$statuses = array(
			'cantfix' => 0,
			'good'    => 1,
			'warning' => 2,
			'bad'     => 3,
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


	/*
	 * Add a message and automatically set the scan status.
	 *
	 * good:    the scan performed correctly and returned a good result.
	 * warning: the scan could not perform correctly.
	 * bad:     the scan performed correctly but returned a bad result.
	 */

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


	// Status and messages for fixes ===============================================================

	// Maybe set current fix status.

	public function set_fix_status( $status, $force = false ) {
		$statuses = array(
			'cantfix' => 0,
			'good'    => 1,
			'warning' => 2,
			'bad'     => 3,
		);

		// Unkown status
		if ( ! isset( $statuses[ $status ] ) ) {
			return false;
		}

		// No previous status
		if ( empty( $this->result_fix['status'] ) || $force ) {
			$this->result_fix['status'] = $status;
			return $status;
		}

		// Status already set: only allow to "upgrade" to a superior status.
		if ( $statuses[ $status ] > $statuses[ $this->result_fix['status'] ] ) {
			$this->result_fix['status'] = $status;
		}

		return $this->result_fix['status'];
	}


	/*
	 * Add a message and automatically set the fix status.
	 *
	 * good:    the fix performed correctly.
	 * warning: partial fix. The fix could not perform entirely: some fix(es) worked and some not.
	 * bad:     error. The fix could not perform correctly.
	 * cantfix: neutral. The flaw cannot be fixed by this plugin.
	 */

	public function add_fix_message( $message_id, $params = array() ) {
		$this->result_fix['msgs'] = isset( $this->result_fix['msgs'] ) ? $this->result_fix['msgs'] : array();
		$this->result_fix['msgs'][ $message_id ] = $params;

		if ( $message_id < 100 ) {

			$this->set_fix_status( 'good' );

		} elseif  ( $message_id < 200 ) {

			$this->set_fix_status( 'warning' );

		} elseif ( $message_id < 300 ) {

			$this->set_fix_status( 'bad' );

		} elseif ( $message_id < 400 ) {

			$this->set_fix_status( 'cantfix' );

		}
	}


	// Are fix status and message(s) set?

	public function has_fix_status() {
		return ! empty( $this->result_fix );
	}


	// Set a fix status + message only if no status is set yet.

	public function maybe_set_fix_status( $message_id, $params = array() ) {
		if ( ! $this->has_fix_status() ) {
			$this->add_fix_message( $message_id, $params );
		}
	}


	// Scan and fix ================================================================================

	// Scan for flow(s).

	public function scan() {
		$this->update();

		$result = $this->result;
		$this->result = array();

		return $result;
	}


	// Try to fix the flaw(s).

	public function fix() {
		$this->update_fix();

		if ( $this->fix_actions ) {
			// Ajax
			if ( defined( 'DOING_AJAX' ) ) {
				// Add the fixes that require user action in the returned data.
				$this->result_fix = array_merge( $this->result_fix, array(
					'form_contents' => $this->get_fix_action_template_parts(),
					'form_fields'   => $this->get_fix_action_fields( $this->fix_actions, false ),
					'form_title'    => _n( 'This action requires your attention', 'These actions require your attention', count( $this->fix_actions ), 'secupress' ),
				) );
			}
			// No ajax
			else {
				// Set a transient with fixes that require user action.
				set_transient( 'secupress_fix_actions', $this->class_name_part . '|' . implode( ',', $this->fix_actions ) );
			}

			$this->fix_actions = array();
		}

		$result = $this->result_fix;
		$this->result_fix = array();

		return $result;
	}


	// Try to fix the flow(s) after requiring user action.

	public function manual_fix() {
		// Don't use `$this->` here, we need to call the one from this class.
		return self::fix();
	}


	// Store IDs related to fixes that require user action.

	final protected function add_fix_action( $fix_id ) {
		$this->fix_actions[ $fix_id ] = $fix_id;
	}


	// Return an array containing the forms that would fix the scan if it requires user action.

	public function get_fix_action_template_parts() {
		return array();
	}


	// Tell if a fix action part is needed.

	protected function has_fix_action_part( $fix_id ) {
		$fix_ids = ! empty( $_POST['test-parts'] ) ? ',' . $_POST['test-parts'] . ',' : '';
		return false !== strpos( $fix_ids, ',' . $fix_id . ',' );
	}


	// Print the required fields for the user fix form.

	public function get_fix_action_fields( $fix_actions, $echo = true ) {
		$output  = '<input type="hidden" name="action" value="secupress_manual_fixit" />';
		$output .= '<input type="hidden" name="test" value="' . $this->class_name_part . '" />';
		$output .= '<input type="hidden" name="test-parts" value="' . implode( ',', array_keys( $fix_actions ) ) . '" />';
		$output .= wp_nonce_field( 'secupress_manual_fixit-' . $this->class_name_part, 'secupress_manual_fixit-nonce', false, false );

		if ( ! $echo ) {
			return $output;
		}
		echo $output;
	}

	// Options =====================================================================================

	// Set option.

	public function update() {
		$name = strtolower( $this->class_name_part );

		if ( ! set_transient( 'secupress_scan_' . $name, $this->result ) ) {
			return array();
		}

		return $this->result;
	}


	public function update_fix() {
		$this->result_fix['attempted_fixes'] = array_key_exists( 'attempted_fixes', $this->result_fix ) ? ++$this->result_fix['attempted_fixes'] : 1;

		$name = strtolower( $this->class_name_part );

		if ( ! set_transient( 'secupress_fix_' . $name, $this->result_fix ) ) {
			return array();
		}

		return $this->result_fix;
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
