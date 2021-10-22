<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * 404s Log class.
 *
 * @package SecuPress
 * @since 1.0
 */
class SecuPress_404_Log extends SecuPress_Log {

	const VERSION = '1.0';


	/** Instance ================================================================================ */

	/**
	 * Constructor.
	 *
	 * @since 1.0
	 *
	 * @param (array|object) $args An array of arguments. If a `WP_Post` is used, it is converted in an adequate array.
	 *                             See `SecuPress_Log::__construct()` for the arguments.
	 *                             The data may need to be preprocessed.
	 */
	public function __construct( $args ) {
		parent::__construct( $args );

		/**
		 * The URI is stored in the post title: add it at the beginning of the data, it will be displayed in the title and the message.
		 */
		$args = get_post( $args );
		
		$this->data = array_merge( array(
			'uri' => '/' . $args->post_title,
		), $this->data );
	}


	/** Private methods ========================================================================= */

	/** Title =================================================================================== */

	/**
	 * Set the Log title.
	 *
	 * @since 1.0
	 */
	protected function set_title( $post = null ) {
		$this->title = __( 'Error 404 for %1$s', 'secupress' );

		parent::set_title( $post );
	}


	/** Message ================================================================================= */

	/**
	 * Set the Log message.
	 *
	 * @since 1.0
	 */
	protected function set_message() {
		$this->message  = __( 'Error 404 for %1$s from IP %4$s', 'secupress' ) . '<br/>';
		$this->message .= sprintf( __( '%s:', 'secupress' ), '<code>$_GET</code>' ) . ' %2$s';
		$this->message .= sprintf( __( '%s:', 'secupress' ), '<code>$_POST</code>' ) . ' %3$s';

		parent::set_message();
	}
}
