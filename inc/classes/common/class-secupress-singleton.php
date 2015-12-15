<?php
defined( 'ABSPATH' ) or die( 'Cheatin\' uh?' );


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
	 * @var The reference to *Singleton* instance of this class.
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
	 * Returns the *Singleton* instance of this class.
	 *
	 * @return Singleton The *Singleton* instance.
	 */
	final public static function get_instance() {
		if ( ! isset( static::$_instance ) ) {
			static::$_instance = new static;
		}

		return static::$_instance;
	}


	/**
	 * Protected constructor to prevent creating a new instance of the *Singleton* via the `new` operator from outside of this class.
	 */
	final private function __construct() {
		$this->_init();
	}


	/**
	 * Private clone method to prevent cloning of the instance of the *Singleton* instance.
	 */
	final private function __clone() {}


	/**
	 * Private unserialize method to prevent unserializing of the *Singleton* instance.
	 */
	final private function __wakeup() {}

}
