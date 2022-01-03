<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * Singleton class.
 *
 * @package SecuPress
 * @since 1.0
 */
class SecuPress_Singleton {

	const VERSION = '1.0';

	/**
	 * Sub-classes must declare a Singleton property as follow:
	 *
	 * The reference to *Singleton* instance of this class.
	 *
	 * @var (object)
	 */
	protected static $_instance;


	/**
	 * Init.
	 * Sub-classes may extend this method.
	 *
	 * @since 1.0
	 */
	protected function _init() {}


	/**
	 * Get the *Singleton* instance of this class.
	 *
	 * @since 1.0
	 *
	 * @return (object) The *Singleton* instance.
	 */
	final public static function get_instance() {
		if ( ! isset( static::$_instance ) ) {
			static::$_instance = new static;
		}

		return static::$_instance;
	}


	/**
	 * Private constructor to prevent creating a new instance of the *Singleton* via the `new` operator from outside of this class.
	 *
	 * @since 1.0
	 */
	final private function __construct() {
		$this->_init();
	}


	/**
	 * Private clone method to prevent cloning of the instance of the *Singleton* instance.
	 *
	 * @since 1.0
	 */
	private function __clone() {}


	/**
	 * Private unserialize method to prevent unserializing of the *Singleton* instance.
	 *
	 * @since 1.0
	 */
	public function __wakeup() {}
}
