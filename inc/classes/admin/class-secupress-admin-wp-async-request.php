<?php
defined( 'ABSPATH' ) or die( 'Cheatin\' uh?' );

if ( ! class_exists( 'WP_Async_Request' ) ) {
	/**
	 * Async request class.
	 *
	 * @package SecuPress
	 * @since 1.0
	 */
	abstract class WP_Async_Request {

		/**
		 * Prefix used to build the global process identifier.
		 *
		 * @var (string)
		 */
		protected $prefix = 'wp';

		/**
		 * Suffix used to build the global process identifier.
		 *
		 * @var (string)
		 */
		protected $action = 'async_request';

		/**
		 * Global process identifier.
		 *
		 * @var (string)
		 */
		protected $identifier;

		/**
		 * Data used during the request.
		 *
		 * @var (array)
		 */
		protected $data = array();

		/**
		 * Initiate new async request.
		 */
		public function __construct() {
			$this->identifier = $this->prefix . '_' . $this->action;

			add_action( 'wp_ajax_' . $this->identifier, array( $this, 'maybe_handle' ) );
			add_action( 'wp_ajax_nopriv_' . $this->identifier, array( $this, 'maybe_handle' ) );
		}

		/**
		 * Set data used during the request.
		 *
		 * @param (array) $data The data.
		 *
		 * @return $this
		 */
		public function data( $data ) {
			$this->data = $data;

			return $this;
		}

		/**
		 * Dispatch the async request.
		 *
		 * @return (array|WP_Error)
		 */
		public function dispatch() {
			$url  = add_query_arg( $this->get_query_args(), $this->get_query_url() );
			$args = $this->get_post_args();
			return wp_remote_post( esc_url_raw( $url ), $args );
		}

		/**
		 * Get query args.
		 *
		 * @return (array)
		 */
		protected function get_query_args() {
			if ( property_exists( $this, 'query_args' ) ) {
				return $this->query_args;
			}

			return array(
				'action' => $this->identifier,
				'nonce'  => wp_create_nonce( $this->identifier ),
			);
		}

		/**
		 * Get query URL.
		 *
		 * @return (string)
		 */
		protected function get_query_url() {
			if ( property_exists( $this, 'query_url' ) ) {
				return $this->query_url;
			}

			return admin_url( 'admin-ajax.php' );
		}

		/**
		 * Get post args.
		 *
		 * @return (array)
		 */
		protected function get_post_args() {
			if ( property_exists( $this, 'post_args' ) ) {
				return $this->post_args;
			}

			return array(
				'timeout'   => 0.01,
				'blocking'  => false,
				'body'      => $this->data,
				'cookies'   => $_COOKIE,
				'sslverify' => apply_filters( 'https_local_ssl_verify', false ),
			);
		}

		/**
		 * Maybe handle.
		 *
		 * Check for correct nonce and pass to handler.
		 */
		public function maybe_handle() {
			secupress_check_admin_referer( $this->identifier, 'nonce' );

			$this->handle();

			wp_die();
		}

		/**
		 * Handle.
		 *
		 * Override this method to perform any actions required
		 * during the async request.
		 */
		abstract protected function handle();
	}
}
