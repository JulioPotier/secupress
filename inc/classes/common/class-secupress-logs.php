<?php
defined( 'ABSPATH' ) or die( 'Cheatin\' uh?' );


/**
 * General Logs class.
 *
 * @package SecuPress
 * @since 1.0
 */

class SecuPress_Logs extends SecuPress_Singleton {

	const VERSION = '1.0';
	/**
	 * @var (object) The reference to the *Singleton* instance of this class: must be extended.
	 */
	protected static $_instance;
	/**
	 * @var (string) The Log type: must be extended.
	 */
	protected $log_type = '';
	/**
	 * @var (int) The Log type priority (order in the tabs): can be extended.
	 */
	protected $log_type_priority = 10;
	/**
	 * @var (array) List of available criticities for this Log type: can be extended.
	 */
	protected $criticities = array( 'normal' );
	/**
	 * @var (array) The Post Type labels: can be extended.
	 */
	protected $post_type_labels = array();
	/**
	 * @var (string) The Post Type.
	 */
	private $post_type = '';
	/**
	 * @var (array) List of all criticities for all Log types.
	 */
	private static $all_criticities = array();


	// Public methods ==============================================================================

	/**
	 * Get the Log type.
	 *
	 * @since 1.0
	 *
	 * @return (string)
	 */
	public function get_log_type() {
		return $this->log_type;
	}


	/**
	 * Get the post type.
	 *
	 * @since 1.0
	 *
	 * @return (string)
	 */
	public function get_post_type() {
		if ( ! $this->post_type ) {
			$this->post_type = static::build_post_type_name( $this->log_type );
		}

		return $this->post_type;
	}


	/**
	 * Get the list of available criticities for this type of Log.
	 *
	 * @since 1.0
	 *
	 * @return (array)
	 */
	public function get_available_criticities() {
		return $this->criticities;
	}


	/**
	 * Get stored Logs.
	 * Some default arguments (like post_type and post_status) are already set by `$this->_logs_query_args()`.
	 *
	 * @since 1.0
	 *
	 * @see https://developer.wordpress.org/reference/functions/get_posts/
	 * @see https://codex.wordpress.org/Class_Reference/WP_Query#Parameters
	 *
	 * @param (array) $args Arguments meant for `WP_Query`.
	 *
	 * @return (array) An array of Logs.
	 */
	public function get_logs( $args = array() ) {
		return get_posts( $this->_logs_query_args( $args ) );
	}


	/**
	 * Delete some Logs.
	 *
	 * @since 1.0
	 *
	 * @param (array) $post_ids An array of post IDs to delete. Omit this parameter to delete all Logs.
	 *
	 * @return (int) Number of deleted Logs.
	 */
	public function delete_logs() {
		global $wpdb;

		$args = func_get_args();

		if ( ! isset( $args[0] ) ) {
			$post_ids = $wpdb->get_col( $wpdb->prepare( "SELECT ID FROM $wpdb->posts WHERE post_type = %s", $this->get_post_type() ) );
		} elseif ( is_array( $args[0] ) ) {
			$post_ids = $args[0];
		} else {
			return 0;
		}

		if ( ! $post_ids ) {
			return 0;
		}

		$deleted = 0;

		foreach ( $post_ids as $post_id ) {
			if ( $this->delete_log( $post_id ) ) {
				++$deleted;
			}
		}

		return $deleted;
	}


	/**
	 * Delete one Log.
	 *
	 * @since 1.0
	 *
	 * @param (int) $post_id The Log ID.
	 *
	 * @return (bool) True, if succeed. False, if failure.
	 */
	public function delete_log( $post_id ) {
		return wp_delete_post( (int) $post_id, true );
	}


	/**
	 * Get the max number of stored Logs of the same type.
	 *
	 * @since 1.0
	 *
	 * @return (int)
	 */
	public function get_logs_limit() {
		/*
		 * Limit the number of Logs stored in the database.
		 * By default 1000, is restricted between 50 and 2000.
		 *
		 * @since 1.0
		 *
		 * @param (int)    The limit.
		 * @param (string) The Log type.
		 */
		$limit = apply_filters( 'secupress.logs.logs_limit', 1000, $this->log_type );

		return secupress_minmax_range( $limit, 50, 2000 );
	}


	/**
	 * Get the URL to download Logs.
	 *
	 * @since 1.0
	 *
	 * @param (string) $referer The page referer.
	 *
	 * @return (string)
	 */
	public function download_logs_url( $referer ) {
		$href = urlencode( $referer );
		$href = admin_url( 'admin-post.php?action=secupress_download-' . $this->log_type . '-logs&_wp_http_referer=' . $href );
		return wp_nonce_url( $href, 'secupress-download-' . $this->log_type . '-logs' );
	}


	/**
	 * Get the URL to delete all Logs.
	 *
	 * @since 1.0
	 *
	 * @param (string) $referer The page referer.
	 *
	 * @return (string)
	 */
	public function delete_logs_url( $referer ) {
		$href = urlencode( $referer );
		$href = admin_url( 'admin-post.php?action=secupress_clear-' . $this->log_type . '-logs&_wp_http_referer=' . $href );
		return wp_nonce_url( $href, 'secupress-clear-' . $this->log_type . '-logs' );
	}


	/**
	 * Get the URL to delete one Log.
	 *
	 * @since 1.0
	 *
	 * @param (int)    $post_id The Log ID.
	 * @param (string) $referer The page referer.
	 *
	 * @return (string)
	 */
	public function delete_log_url( $post_id, $referer ) {
		$href = urlencode( $referer );
		$href = admin_url( 'admin-post.php?action=secupress_delete-' . $this->log_type . '-log&log=' . $post_id . '&_wp_http_referer=' . $href );
		return wp_nonce_url( $href, 'secupress-delete-' . $this->log_type . '-log' );
	}


	// Private methods =============================================================================

	/**
	 * Launch main hooks.
	 *
	 * @since 1.0
	 */
	protected function _init() {
		static $done = false;

		// Register the Post Type.
		$this->_register_post_type();

		// Filter the post slug to allow duplicates.
		add_filter( 'wp_unique_post_slug', array( $this, '_allow_log_name_duplicates' ), 10, 6 );

		if ( is_admin() ) {
			self::$all_criticities = array_merge( self::$all_criticities, $this->criticities );

			// For the page that lists Logs, "register" our Log type.
			add_filter( '_secupress.logs.log_types', array( $this, '_register_log_type' ), $this->log_type_priority );

			// Filter the query args used in `SecuPress_Logs_List_Table::prepare_items()`.
			add_filter( '_secupress.logs.logs_query_args', array( $this, '_logs_query_args_filter' ) );

			// Filter the available post statuses.
			add_filter( 'wp_count_posts', array( $this, '_count_posts_filter' ), 10, 2 );

			// Create the page that lists the Logs.
			add_action( ( is_multisite() ? 'network_' : '' ) . 'admin_menu', array( $this, '_maybe_create_page' ), 11 );

			// Download Logs list.
			add_action( 'admin_post_secupress_download-' . $this->log_type . '-logs',    array( $this, '_post_download_logs_ajax_post_cb' ) );

			// Empty Logs list.
			add_action( 'wp_ajax_secupress_clear-' . $this->log_type . '-logs',          array( $this, '_ajax_clear_logs_ajax_post_cb' ) );
			add_action( 'admin_post_secupress_clear-' . $this->log_type . '-logs',       array( $this, '_post_clear_logs_ajax_post_cb' ) );

			// Bulk delete Logs.
			add_action( 'wp_ajax_secupress_bulk_delete-' . $this->log_type . '-logs',    array( $this, '_ajax_bulk_delete_logs_ajax_post_cb' ) );
			add_action( 'admin_post_secupress_bulk_delete-' . $this->log_type . '-logs', array( $this, '_post_bulk_delete_logs_ajax_post_cb' ) );

			// Delete a Log.
			add_action( 'wp_ajax_secupress_delete-' . $this->log_type . '-log',          array( $this, '_ajax_delete_log_ajax_post_cb' ) );
			add_action( 'admin_post_secupress_delete-' . $this->log_type . '-log',       array( $this, '_post_delete_log_ajax_post_cb' ) );
		}

		if ( ! $done ) {
			$done = true;

			// Register the Post Statuses.
			add_action( 'init', array( __CLASS__, '_register_post_statuses' ) );
		}
	}


	/**
	 * Register the Post Type.
	 * Labels can be customized with `$this->post_type_labels`.
	 *
	 * @since 1.0
	 */
	public function _register_post_type() {
		if ( ! $this->post_type_labels ) {
			$this->post_type_labels = array(
				'name'                  => _x( 'Logs', 'post type general name', 'secupress' ),
				'singular_name'         => _x( 'Log', 'post type singular name', 'secupress' ),
				'menu_name'             => _x( 'Logs', 'post type general name', 'secupress' ),
				'all_items'             => __( 'All Logs', 'secupress' ),
				'add_new'               => _x( 'Add New', 'secupress_log', 'secupress' ),
				'add_new_item'          => __( 'Add New Log', 'secupress' ),
				'edit_item'             => __( 'Edit Log', 'secupress' ),
				'new_item'              => __( 'New Log', 'secupress' ),
				'view_item'             => __( 'View Log', 'secupress' ),
				'items_archive'         => _x( 'Logs', 'post type general name', 'secupress' ),
				'search_items'          => __( 'Search Logs', 'secupress' ),
				'not_found'             => __( 'No logs found.', 'secupress' ),
				'not_found_in_trash'    => __( 'No logs found in Trash.', 'secupress' ),
				'parent_item_colon'     => __( 'Parent Log:', 'secupress' ),
				'archives'              => __( 'Log Archives', 'secupress' ),
				'insert_into_item'      => __( 'Insert into log', 'secupress' ),
				'uploaded_to_this_item' => __( 'Uploaded to this log', 'secupress' ),
				'filter_items_list'     => __( 'Filter logs list', 'secupress' ),
				'items_list_navigation' => __( 'Logs list navigation', 'secupress' ),
				'items_list'            => __( 'Logs list', 'secupress' ),
			);
		}

		register_post_type( $this->get_post_type(), array(
			'labels'              => $this->post_type_labels,
			'capability_type'     => $this->get_post_type(),
			'supports'            => false,
			'rewrite'             => false,
			'map_meta_cap'        => true,
			'capabilities'        => array(
				'read' => 'read_' . $this->get_post_type() . 's',
			),
		) );
	}


	/**
	 * Filter the unique post slug: we need to allow duplicates.
	 *
	 * @since 1.0
	 *
	 * @param (string) $slug          The post slug.
	 * @param (int)    $post_ID       Post ID.
	 * @param (string) $post_status   The post status.
	 * @param (string) $post_type     Post type.
	 * @param (int)    $post_parent   Post parent ID
	 * @param (string) $original_slug The original post slug.
	 *
	 * @return (string) The slug.
	 */
	public function _allow_log_name_duplicates( $slug, $post_ID, $post_status, $post_type, $post_parent, $original_slug ) {
		if ( $this->get_post_type() !== $post_type ) {
			return $slug;
		}

		/**
		 * The slug should be provided with a "secupress_" prefix.
		 * That way, when `wp_unique_post_slug()` checks for duplicates, it won't find any, we save one useless request to the database.
		 */
		return preg_replace( '/^secupress_/', '', $original_slug );
	}


	/**
	 * Add the current Log type to the Logs list.
	 *
	 * @since 1.0
	 *
	 * @param (array) Array of arrays with Log type as key and current class name + post type as values.
	 *
	 * @return (array)
	 */
	public function _register_log_type( $types ) {
		$log_type  = $this->get_log_type();
		$post_type = $this->get_post_type();

		$types[ $log_type ] = array(
			'classname' => get_class( $this ),
			'post_type' => $post_type,
		);

		return $types;
	}


	/**
	 * Filter the default query args: if the post type matches, apply the default args.
	 *
	 * @since 1.0
	 *
	 * @param (array) $args Original args, containing at least the post type.
	 *
	 * @return (array)
	 */
	public function _logs_query_args_filter( $args ) {
		if ( ! empty( $args['post_type'] ) && $this->get_post_type() === $args['post_type'] ) {
			return $this->_logs_query_args( $args );
		}

		return $args;
	}


	/**
	 * Filter the available post statuses.
	 *
	 * @since 1.0
	 *
	 * @param (object) $counts Number of posts for each status.
	 * @param (string) $type   The corresponding post type.
	 *
	 * @return (object)
	 */
	public function _count_posts_filter( $counts, $type ) {
		if ( $this->get_post_type() === $type ) {
			return (object) array_intersect_key( (array) $counts, array_flip( $this->criticities ) );
		}

		return $counts;
	}


	/**
	 * Register the Post Statuses.
	 *
	 * @since 1.0
	 */
	public static function _register_post_statuses() {
		$criticities = array(
			'high'   => array(
				'label'       => __( 'High', 'secupress' ),
				'label_count' => _n_noop( 'High criticity <span class="count">(%s)</span>', 'High criticity <span class="count">(%s)</span>', 'secupress' ),
				'public'      => false,
				'internal'    => true,
				'protected'   => true,
				'private'     => true,
			),
			'normal' => array(
				'label'       => __( 'Normal', 'secupress' ),
				'label_count' => _n_noop( 'Normal criticity <span class="count">(%s)</span>', 'Normal criticity <span class="count">(%s)</span>', 'secupress' ),
				'public'      => false,
				'internal'    => true,
				'protected'   => true,
				'private'     => true,
			),
			'low'    => array(
				'label'       => __( 'Low', 'secupress' ),
				'label_count' => _n_noop( 'Low criticity <span class="count">(%s)</span>', 'Low criticity <span class="count">(%s)</span>', 'secupress' ),
				'public'      => false,
				'internal'    => true,
				'protected'   => true,
				'private'     => true,
			),
		);

		self::$all_criticities = array_flip( self::$all_criticities );

		foreach ( $criticities as $criticity => $atts ) {
			if ( isset( self::$all_criticities[ $criticity ] ) ) {
				register_post_status( $criticity, $atts );
			}
		}
	}


	/**
	 * Create the page displaying the Logs.
	 *
	 * @since 1.0
	 */
	public function _maybe_create_page() {
		// To create the menu item and the page, we need to use the class used for the current Log type.
		$log_types = static::_get_log_types();
		$log_type  = ! empty( $_GET['tab'] ) ? $_GET['tab'] : '';
		$log_type  = $log_type && isset( $log_types[ $log_type ] ) ? $log_type : key( $log_types );

		if ( $this->log_type !== $log_type ) {
			return;
		}

		// Create the menu item.
		add_submenu_page(
			'secupress',
			_x( 'Logs', 'post type general name', 'secupress' ),
			_x( 'Logs', 'post type general name', 'secupress' ),
			secupress_get_capability(),
			'secupress_logs',
			array( $this, '_page' )
		);

		// Initiate the page.
		add_action( 'load-secupress_page_secupress_logs', array( $this, '_logs_list_load' ) );
	}


	/**
	 * Prepare the list.
	 *
	 * @since 1.0
	 */
	public function _logs_list_load() {
		$classname = static::_maybe_include_list_class();
		$classname::get_instance()->_prepare_list();
	}


	/**
	 * The page content.
	 *
	 * @since 1.0
	 */
	public function _page() {
		$classname = static::_maybe_include_list_class();
		$classname::get_instance()->_display_list();
	}


	/**
	 * Store new Logs. If the maximum number of Logs is reached, the oldest ones are deleted.
	 *
	 * @since 1.0
	 *
	 * @param (array) $new_logs The new Logs: an array of arrays.
	 *
	 * @return (int) Number of Logs added.
	 */
	protected function _save_logs( $new_logs ) {
		global $blog_id;

		if ( ! $new_logs ) {
			return 0;
		}

		$switched = false;
		$added    = 0;

		if ( is_multisite() && secupress_get_main_blog_id() !== (int) $blog_id ) {
			// On multisites, create posts in the main blog.
			switch_to_blog( secupress_get_main_blog_id() );
			$switched = true;
		}

		// A post author is needed.
		$user_id = get_users( array(
			'blog_id'     => secupress_get_main_blog_id(),
			'role'        => 'administrator',
			'number'      => 1,
			'fields'      => 'ID',
			'count_total' => false,
		) );
		$user_id = (int) reset( $user_id );
		/**
		 * Filter the Logs author.
		 *
		 * @since 1.0
		 *
		 * @param (int) $user_id A user ID. That should be a user that won't be deleted anytime soon.
		 */
		$user_id = apply_filters( 'secupress.logs.author', $user_id );

		foreach ( $new_logs as $new_log ) {
			$args = array(
				'post_type'   => $this->get_post_type(), // Post type / Action, 404.
				'post_date'   => $new_log['time'],       // Post date / Time.
				'menu_order'  => 0,                      // Menu order / Microtime.
				'post_status' => 'normal',               // Post status / Criticity.
				'post_author' => $user_id,               // Post author: needed to create the post, we don't want the current user to create it.
			);

			// Menu order / Microtime.
			if ( ! empty( $new_log['order'] ) ) {
				if ( ! is_int( $new_log['order'] ) ) {
					// It's a microtime.
					$new_log['order'] = explode( ' ', $new_log['order'] );  // array( '0.03746700', '1452528510' )
					$new_log['order'] = reset( $new_log['order'] );         // '0.03746700'
					$new_log['order'] = explode( '.', $new_log['order'] );  // array( '0', '03746700' )
					$new_log['order'] = end( $new_log['order'] );           // '03746700'
					$new_log['order'] = (int) str_pad( $new_log['order'], 8, '0', STR_PAD_RIGHT ); // We make sure we have '03746700', not '037467'.
				}

				$args['menu_order'] = $new_log['order'];
			}

			// Post name / Type: option, network_option, action, filter, err404. Some of them are suffixed with `|add` or `|update`.
			if ( ! empty( $new_log['type'] ) ) {
				$args['post_name'] = str_replace( '|', '-', $new_log['type'] );
			}

			// Post title / Target: option name, action name, filter name, URI.
			if ( ! empty( $new_log['target'] ) ) {
				$args['post_title'] = $new_log['target'];
			}

			// Post status / Criticity.
			if ( ! empty( $new_log['critic'] ) ) {
				$args['post_status'] = $new_log['critic'];
			}

			// Guid: don't let WordPress do its stuff.
			$args['guid'] = $args['post_date'] . str_pad( $args['menu_order'], 8, '0', STR_PAD_RIGHT );
			$args['guid'] = str_replace( array( ' ', '-', ':' ), '', $args['guid'] );

			// Create the Log.
			if ( $post_id = wp_insert_post( $args ) ) {
				// Meta: data.
				if ( ! empty( $new_log['data'] ) ) {
					update_post_meta( $post_id, 'data', $new_log['data'] );
				}

				// Meta: user IP.
				if ( ! empty( $new_log['user_ip'] ) ) {
					update_post_meta( $post_id, 'user_ip', esc_html( $new_log['user_ip'] ) );
				}

				// Meta: user ID.
				if ( ! empty( $new_log['user_id'] ) ) {
					update_post_meta( $post_id, 'user_id', (int) $new_log['user_id'] );
				}

				// Meta: user login.
				if ( ! empty( $new_log['user_login'] ) ) {
					update_post_meta( $post_id, 'user_login', esc_html( $new_log['user_login'] ) );
				}

				++$added;
			}
		}

		// Limit the number of Logs stored in the database.
		if ( $added ) {
			$limit = $this->get_logs_limit();
			$logs  = $this->get_logs( array(
				'fields'         => 'ids',
				'offset'         => $limit,
				'posts_per_page' => $limit, // If -1, 'offset' won't work. Any large number does the trick.
			) );

			if ( $logs ) {
				foreach ( $logs as $post_id ) {
					$this->delete_log( $post_id );
				}
			}
		}

		if ( $switched ) {
			restore_current_blog();
		}

		return $added;
	}


	// Admin post / Admin ajax =====================================================================

	/**
	 * Admin post callback that allows to download the Logs of a certain type as a .txt file.
	 *
	 * @since 1.0
	 */
	public function _post_download_logs_ajax_post_cb() {
		check_admin_referer( 'secupress-download-' . $this->log_type . '-logs' );

		if ( ! static::_user_can() ) {
			wp_nonce_ays( '' );
		}

		if ( ini_get( 'zlib.output_compression' ) ) {
			ini_set( 'zlib.output_compression', 'Off' );
		}

		$filename = SECUPRESS_PLUGIN_SLUG . '-' . $this->log_type . '-logs.txt';
		$logs     = $this->get_logs();

		set_time_limit( 0 );

		ob_start();
		nocache_headers();
		header( 'Content-Type: text/plain; charset=' . get_option( 'blog_charset' ) );
		header( 'Content-Disposition: attachment; filename="' . $filename . '"' );
		header( 'Content-Transfer-Encoding: binary' );
		header( 'Connection: close' );
		ob_end_clean();
		flush();

		if ( $logs && is_array( $logs ) ) {
			$classname  = static::_maybe_include_log_class();
			$log_header = str_pad( '==%SECUPRESS-LOG%', 100, '=', STR_PAD_RIGHT ) . "\n";

			foreach ( $logs as $log ) {
				$log = new $classname( $log );

				echo $log_header;
				echo $this->_get_log_header_for_file( $log ) . "\n";
				echo html_entity_decode( strip_tags( str_replace( '<br/>', "\n", $log->get_message() ) ) );
				echo "\n\n";
			}
		}
		die;
	}


	/**
	 * Ajax callback that allows to delete all Logs of a certain type.
	 *
	 * @since 1.0
	 */
	public function _ajax_clear_logs_ajax_post_cb() {
		check_ajax_referer( 'secupress-clear-' . $this->log_type . '-logs' );

		if ( ! static::_user_can() ) {
			wp_send_json_error();
		}

		$this->delete_logs();

		wp_send_json_success( __( 'Logs deleted.', 'secupress' ) );
	}


	/**
	 * Admin post callback that allows to delete all Logs of a certain type.
	 *
	 * @since 1.0
	 */
	public function _post_clear_logs_ajax_post_cb() {
		check_admin_referer( 'secupress-clear-' . $this->log_type . '-logs' );

		if ( ! static::_user_can() ) {
			wp_nonce_ays( '' );
		}

		$this->delete_logs();

		add_settings_error( 'general', 'logs_cleared', __( 'Logs deleted.', 'secupress' ), 'updated' );
		set_transient( 'settings_errors', get_settings_errors(), 30 );

		$goback = add_query_arg( 'settings-updated', 'true',  wp_get_referer() );
		wp_redirect( $goback );
		die();
	}


	/**
	 * Ajax callback that allows to delete several Logs of a certain type.
	 *
	 * @since 1.0
	 */
	public function _ajax_bulk_delete_logs_ajax_post_cb() {
		check_ajax_referer( 'secupress-bulk-' . $this->log_type . '-log' );

		if ( ! static::_user_can() ) {
			wp_send_json_error();
		}

		if ( empty( $_GET['post'] ) || ! is_array( $_GET['post'] ) ) {
			wp_send_json_error( sprintf( _n( '%s Log deleted.', '%s Logs deleted.', 0, 'secupress' ), 0 ) );
		}

		$deleted = $this->delete_logs( $_GET['post'] );

		wp_send_json_success( sprintf( _n( '%s log permanently deleted.', '%s logs permanently deleted.', $deleted, 'secupress' ), number_format_i18n( $deleted ) ) );
	}


	/**
	 * Admin post callback that allows to delete several Logs of a certain type.
	 *
	 * @since 1.0
	 */
	public function _post_bulk_delete_logs_ajax_post_cb() {
		check_admin_referer( 'secupress-bulk-' . $this->log_type . '-logs' );

		if ( ! static::_user_can() ) {
			wp_nonce_ays( '' );
		}

		if ( empty( $_GET['post'] ) || ! is_array( $_GET['post'] ) ) {
			$deleted = 0;
		} else {
			$deleted = $this->delete_logs( $_GET['post'] );
		}

		add_settings_error( 'general', 'logs_bulk_deleted', sprintf( _n( '%s log permanently deleted.', '%s logs permanently deleted.', $deleted, 'secupress' ), number_format_i18n( $deleted ) ), 'updated' );
		set_transient( 'settings_errors', get_settings_errors(), 30 );

		$goback = add_query_arg( 'settings-updated', 'true',  wp_get_referer() );
		wp_redirect( $goback );
		die();
	}


	/**
	 * Ajax callback that allows to delete a Log.
	 *
	 * @since 1.0
	 */
	public function _ajax_delete_log_ajax_post_cb() {
		check_ajax_referer( 'secupress-delete-' . $this->log_type . '-log' );

		if ( empty( $_GET['log'] ) ) {
			wp_send_json_error();
		}

		if ( ! static::_user_can() ) {
			wp_send_json_error();
		}

		if ( ! $this->delete_log( $_GET['log'] ) ) {
			wp_send_json_error();
		}

		wp_send_json_success( __( 'Log permanently deleted.', 'secupress' ) );
	}


	/**
	 * Admin post callback that allows to delete a Log.
	 *
	 * @since 1.0
	 */
	public function _post_delete_log_ajax_post_cb() {
		check_admin_referer( 'secupress-delete-' . $this->log_type . '-log' );

		if ( empty( $_GET['log'] ) ) {
			wp_nonce_ays( '' );
		}

		if ( ! static::_user_can() ) {
			wp_nonce_ays( '' );
		}

		if ( ! $this->delete_log( $_GET['log'] ) ) {
			wp_nonce_ays( '' );
		}

		add_settings_error( 'general', 'log_deleted', __( 'Log permanently deleted.', 'secupress' ), 'updated' );
		set_transient( 'settings_errors', get_settings_errors(), 30 );

		$goback = add_query_arg( 'settings-updated', 'true',  wp_get_referer() );
		wp_redirect( $goback );
		die();
	}


	// Tools =======================================================================================

	/**
	 * Create a Post Type name based on a Log type.
	 *
	 * @since 1.0
	 *
	 * @param (string) $log_type A Log type.
	 *
	 * @return (string) The corresponding Post Type name.
	 */
	public static function build_post_type_name( $log_type ) {
		return 'secupress_log_' . $log_type;
	}


	/**
	 * Get Log Types.
	 *
	 * @since 1.0
	 *
	 * @return (string)
	 */
	public static function _get_log_types() {
		/**
		 * Filter the Log types available. All Log types must be registered here.
		 *
		 * @since 1.0
		 *
		 * @see `$this->_register_log_type()`
		 *
		 * @param (array) An array of arrays with the Log type as key and containing the post type and the name of the "logs class" as values.
		 */
		return apply_filters( '_secupress.logs.log_types', array() );
	}


	/**
	 * Build args for a Logs query.
	 *
	 * @since 1.0
	 *
	 * @param (array) $args Some `WP_Query` arguments.
	 *
	 * @return (array) The new args merged with default args.
	 */
	public function _logs_query_args( $args = array() ) {
		return array_merge( array(
			'post_type'      => $this->get_post_type(),
			'post_status'    => $this->criticities,
			'posts_per_page' => -1,
			'orderby'        => 'date menu_order',
			'order'          => 'ASC',
		), $args );
	}


	/**
	 * Used when creating a Log to set default values: time, order, user_ip, user_id, and user_login.
	 * If the user does not exists, user_id and user_login are not set.
	 *
	 * @since 1.0
	 *
	 * @param (array) $log A Log.
	 *
	 * @return (array)
	 */
	public static function _set_log_time_and_user( $log = array() ) {
		$log['time']    = current_time( 'mysql' );
		$log['order']   = microtime();
		$log['user_id'] = get_current_user_id();
		$log['user_ip'] = secupress_get_ip();

		if ( $log['user_id'] ) {
			$user = get_userdata( $log['user_id'] );

			if ( $user ) {
				$log['user_login'] = $user->user_login;
			} else {
				unset( $log['user_id'] );
			}
		}

		return $log;
	}


	/**
	 * Tell if the current user can download or delete Logs.
	 *
	 * @since 1.0
	 *
	 * @return (bool).
	 */
	protected static function _user_can() {
		return current_user_can( secupress_get_capability() );
	}


	/**
	 * Get the header content used in the `.txt` file that the user can download.
	 *
	 * @since 1.0
	 *
	 * @param (object) `SecuPress_Log` object.
	 *
	 * @return (string) The header content.
	 */
	public function _get_log_header_for_file( $log ) {
		$out = '[' . $log->get_time();

		if ( count( $this->criticities ) > 1 ) {
			$out .= ' | ' . $log->get_criticity();
		}

		$out .= ' | ' . $log->get_user() . ']';
		return $out;
	}


	/**
	 * Include the file containing the class `Secupress_Log` if not already done.
	 * Must be extended and must return the class name.
	 *
	 * @since 1.0
	 *
	 * @return (string) The Log class name.
	 */
	public static function _maybe_include_log_class() {
		if ( ! class_exists( 'SecuPress_Log' ) ) {
			secupress_require_class( 'Log' );
		}

		return 'SecuPress_Log';
	}


	/**
	 * Include the file containing the class `Secupress_Logs_List` if not already done.
	 *
	 * @since 1.0
	 *
	 * @return (string) The Logs List class name.
	 */
	private static function _maybe_include_list_class() {
		if ( ! class_exists( 'SecuPress_Logs_List' ) ) {
			secupress_require_class( 'Logs', 'List' );
		}

		return 'SecuPress_Logs_List';
	}

}
