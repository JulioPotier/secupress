<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * HTTP Logs class.
 *
 * @package SecuPress
 * @since 2.1
 */
class SecuPress_HTTP_Logs extends SecuPress_Logs {

	const VERSION = '1.0';

	/**
	 * The reference to *Singleton* instance of this class.
	 *
	 * @var (object)
	 */
	protected static $_instance;

	/**
	 * The Log type.
	 *
	 * @var (string)
	 */
	protected $log_type = 'http';


	/** Private methods ========================================================================= */

	/**
	 * Launch main hooks.
	 *
	 * @since 2.1
	 */
	protected function _init() {
		// Labels for the Custom Post Type.
		$this->post_type_labels = array(
			'name'                  => _x( 'HTTP Logs', 'post type general name', 'secupress' ),
			'singular_name'         => _x( 'HTTP Log', 'post type singular name', 'secupress' ),
			'menu_name'             => _x( 'HTTP Logs', 'post type general name', 'secupress' ),
			'all_items'             => __( 'All HTTP Logs', 'secupress' ),
			'add_new'               => _x( 'Add New', 'secupress_log', 'secupress' ),
			'add_new_item'          => __( 'Add New HTTP Log', 'secupress' ),
			'edit_item'             => __( 'Edit HTTP Log', 'secupress' ),
			'new_item'              => __( 'New HTTP Log', 'secupress' ),
			'view_item'             => __( 'View HTTP Log', 'secupress' ),
			'items_archive'         => _x( 'HTTP Logs', 'post type general name', 'secupress' ),
			'search_items'          => __( 'Search HTTP Logs', 'secupress' ),
			'not_found'             => __( 'No HTTP logs found.', 'secupress' ),
			'not_found_in_trash'    => __( 'No HTTP logs found in Trash.', 'secupress' ),
			'parent_item_colon'     => __( 'Parent HTTP Log:', 'secupress' ),
			'archives'              => __( 'HTTP Log Archives', 'secupress' ),
			'insert_into_item'      => __( 'Insert into HTTP log', 'secupress' ),
			'uploaded_to_this_item' => __( 'Uploaded to this HTTP log', 'secupress' ),
			'filter_items_list'     => __( 'Filter HTTP logs list', 'secupress' ),
			'items_list_navigation' => __( 'HTTP Logs list navigation', 'secupress' ),
			'items_list'            => __( 'HTTP Logs list', 'secupress' ),
		);

		// Log the HTTP.
		add_action( 'http_api_debug', [ $this, 'log_http' ], 10, 5 );

		add_filter( 'manage_' . SecuPress_Logs::build_post_type_name( $this->log_type ) . '_posts_columns', [ $this, 'manage_column' ] );

		add_action( 'manage_' . SecuPress_Logs::build_post_type_name( $this->log_type ) . '_posts_custom_column', [ $this, 'column_content' ], 10, 2 );

		add_filter( 'secupress.logs.logs_query_args', function( $args ) { $args['order'] = 'ASC'; return $args; } );

		add_filter( 'before_delete_post', [ $this, 'before_delete_post' ] );

		// Parent hooks.
		parent::_init();
	}

	public function before_delete_post( $post_id ) {

		global $wpdb;

		$children_query = $wpdb->prepare( "SELECT ID, post_status FROM $wpdb->posts WHERE post_parent = %d", $post_id );
		$children = $wpdb->get_results( $children_query );

		if ( $children ) {
			foreach ( $children as $child ) {
				wp_delete_post( $child->ID, true );
			}
		}
	}

	public function logs_query_args_filter( $args ) {
		$args['post_parent'] = isset( $_GET['log'] ) ? null : 0;
		return $args;
	}
	public function manage_column( $posts_columns ) {
		$posts_columns['counter'] = __( 'Counter', 'secupress' );
		unset( $posts_columns['date'] );
		// $posts_columns['from'] = __( 'Date', 'secupress' );
		return $posts_columns;
	}

	public function column_content( $column_name, $post_ID ) {
		if ( 'counter' === $column_name ) {
			$counter = (int) get_post_meta( $post_ID, '_' . SecuPress_Logs::build_post_type_name( $this->log_type ) . '_counter', true );
			$now     = time();
			$from    = (int) get_post_meta( $post_ID, '_' . SecuPress_Logs::build_post_type_name( $this->log_type ) . '_from', true );
			$offset  = $now - $from;
			$ratio   = round( $offset / $counter );
			if ( $counter > 1 ) {
				printf( _n( '<strong>%1$s call</strong><br><em>Every %2$s</em>', '<strong>%1$s calls</strong><br><em>Every %2$s</em>', $counter, 'secupress' ), number_format_i18n( $counter ), secupress_readable_duration( $ratio ) );
			} else {
				printf( __( '<strong>1 call</strong> <em>since %s</em>', 'secupress' ), secupress_readable_duration( $ratio ) );
			}
		}
	}

	/**
	 * Log a HTTP.
	 *
	 * @since 2.1
	 */
	public function log_http( $response, $dummy, $class, $parsed_args, $url ) {
		// Build the Log array.
		$post_type  = SecuPress_Logs::build_post_type_name( $this->log_type );
		$parsed_url = shortcode_atts( [ 'scheme' => '', 'host' => '', 'path' => '', 'query' => '' ], wp_parse_url( $url ) );
		$parsed_args['_class'] = $class;

		// Manage "host"
		$host_name = $parsed_url['scheme'] . '://' . $parsed_url['host'];
		if ( ! $host_parent = get_page_by_title( esc_html( $host_name ), OBJECT, $post_type ) ) {
			$log = static::set_log_time_and_user( [
				'type'        => 'http',
				'target'      => esc_html( $host_name ),
			] );
			$host_id = parent::save_logs( [ $log ] )[0];
			update_post_meta( $host_id, '_' . $post_type . '_counter', 1 );
			update_post_meta( $host_id, '_' . $post_type . '_from', time() );
		// else "host"
		} else {
			$host_id = $host_parent->ID; // used as parent later
			$counter = get_post_meta( $host_parent->ID, '_' . $post_type . '_counter', true );
			$counter++;
			update_post_meta( $host_parent->ID, '_' . $post_type . '_counter', $counter );
		}
		$this->add_history( $host_id, compact( 'url', 'parsed_args', 'response' ) );

		// Manage "query"
		if ( ( ! empty( $parsed_url['path'] ) && '/' !== $parsed_url['path'] ) || ( ! empty( $parsed_url['query'] ) && '?' !== $parsed_url['query'] ) ) {
			$_path  = '/' !== $parsed_url['path']  ? $parsed_url['path']  : '';
			$_query = '?' !== $parsed_url['query'] ? '?' . $parsed_url['query'] : '';
			$query_name = $parsed_url['scheme'] . '://' . untrailingslashit( $parsed_url['host'] ) . $_path . $_query;
			if ( ! $query_parent = get_page_by_title( esc_html( $query_name ), OBJECT, $post_type ) ) {
				$log = static::set_log_time_and_user( [
					'type'        => 'http',
					'target'      => esc_html( $query_name ),
					'parent' => $host_id,
				] );
				$query_id = parent::save_logs( [ $log ] )[0];
				update_post_meta( $query_id, '_' . $post_type . '_counter', 1 );
				update_post_meta( $query_id, '_' . $post_type . '_from', time() );
			// else "query"
			} else {
				$counter = get_post_meta( $query_parent->ID, '_' . $post_type . '_counter', true );
				$counter++;
				$query_id = $query_parent->ID;
				update_post_meta( $query_parent->ID, '_' . $post_type . '_counter', $counter );
			}
			$this->add_history( $query_id, compact( 'url', 'parsed_args', 'response' ) );
		}
	}


	/** Tools =================================================================================== */

	/**
	 * Add a history entry for a HTTP log, limited to 10 entries
	 *
	 * @since 2.1
	 *
	 * @param (int)   $log_id
	 * @param (array) $args
	 */
	public function add_history( $log_id, $args ) {
		$post_type         = SecuPress_Logs::build_post_type_name( $this->log_type );
		$history           = get_post_meta( $log_id, '_' . $post_type . '_history', true );
		$history           = is_array( $history ) ? $history : [];
		$history           = array_reverse( $history, true );
		$history[ time() ] = $args;
		$history           = array_slice( $history, 0, 10, true );
		$history           = array_reverse( $history, true );
		update_post_meta( $log_id, '_' . $post_type . '_history', $history );
	}
	/**
	 * Include the files containing the classes `Secupress_Log` and `SecuPress_HTTP_Log` if not already done.
	 *
	 * @since 2.1
	 *
	 * @return (string) The Log class name.
	 */
	public static function maybe_include_log_class() {
		// The parent class is needed.
		parent::maybe_include_log_class();

		if ( ! class_exists( 'SecuPress_HTTP_Log' ) ) {
			require_once( dirname( __FILE__ ) . '/class-secupress-http-log.php' );
		}

		return 'SecuPress_HTTP_Log';
	}
}
