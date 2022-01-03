<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * General Logs class.
 *
 * @package SecuPress
 * @since 1.0
 */
class SecuPress_Logs extends SecuPress_Singleton {

	const VERSION = '1.0.1';

	/**
	 * The reference to the *Singleton* instance of this class: must be extended.
	 *
	 * @var (object)
	 */
	protected static $_instance;

	/**
	 * The Log type: must be extended.
	 *
	 * @var (string)
	 */
	protected $log_type = '';

	/**
	 * The Log type priority (order in the tabs): can be extended.
	 *
	 * @var (int)
	 */
	protected $log_type_priority = 10;

	/**
	 * List of available criticities for this Log type: can be extended.
	 *
	 * @var (array)
	 */
	protected $criticities = array( 'normal' );

	/**
	 * The Post Type labels: can be extended.
	 *
	 * @var (array)
	 */
	protected $post_type_labels = array();

	/**
	 * The Post Type.
	 *
	 * @var (string)
	 */
	private $post_type = '';

	/**
	 * The name of the transient that will store the delayed Logs.
	 *
	 * @var (string)
	 */
	private $delayed_logs_transient_name = '';

	/**
	 * List of all criticities for all Log types.
	 *
	 * @var (array)
	 */
	private static $all_criticities = array();


	/** Public methods ========================================================================== */

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
	 * Some default arguments (like post_type and post_status) are already set by `$this->logs_query_args()`.
	 *
	 * @since 1.0
	 *
	 * @see https://developer.wordpress.org/reference/functions/get_posts/.
	 * @see https://codex.wordpress.org/Class_Reference/WP_Query#Parameters.
	 *
	 * @param (array) $args Arguments meant for `WP_Query`.
	 *
	 * @return (array) An array of Logs.
	 */
	public function get_logs( $args = array() ) {
		return get_posts( $this->logs_query_args( $args ) );
	}


	/**
	 * Get Logs with a certain user ID.
	 *
	 * @since 1.0
	 *
	 * @param (int)  $id       A user ID.
	 * @param (bool) $ids_only Return an array of IDs instead of an array of posts.
	 *
	 * @return (array) An array of Logs or IDs.
	 */
	public function get_logs_from_user_id( $id, $ids_only = false ) {
		$id   = (int) $id;
		$args = array(
			'meta_query' => array(),
		);

		if ( $ids_only ) {
			$args['fields'] = 'ids';
		}

		if ( $id ) {
			// Logs with this user ID.
			$args['meta_query'][] = array(
				'key'   => 'user_id',
				'value' => $id,
				'type'  => 'NUMERIC',
			);
		} else {
			// Logs without user ID.
			$meta = array(
				'key'     => 'user_id',
				'compare' => 'NOT EXISTS',
			);

			$args['meta_query'][] = $meta;
		}

		return $this->get_logs( $args );
	}


	/**
	 * Get Logs with a certain IP address.
	 *
	 * @since 1.0
	 *
	 * @param (string) $ip       An IP address.
	 * @param (bool)   $ids_only Return an array of IDs instead of an array of posts.
	 *
	 * @return (array) An array of Logs or IDs.
	 */
	public function get_logs_from_ip( $ip, $ids_only = false ) {
		$args = array(
			'meta_query' => array(
				array(
					'key'   => 'user_ip',
					'value' => $ip,
				),
			),
		);

		if ( $ids_only ) {
			$args['fields'] = 'ids';
		}

		return $this->get_logs( $args );
	}


	/**
	 * Delete some Logs.
	 *
	 * @since 1.0
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

		// Delete Postmeta.
		$sql = sprintf( "DELETE FROM $wpdb->postmeta WHERE post_id IN (%s)", implode( ',', $post_ids ) );
		$wpdb->query( $sql ); // WPCS: unprepared SQL ok.

		// Delete Posts.
		$sql = sprintf( "DELETE FROM $wpdb->posts WHERE ID IN (%s)", implode( ',', $post_ids ) );
		$wpdb->query( $sql ); // WPCS: unprepared SQL ok.

		return count( $post_ids );
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
		/**
		 * Limit the number of Logs stored in the database.
		 * By default 1000, is restricted between 10 and 10000.
		 *
		 * @since 1.0
		 *
		 * @param (int)    $limit          The limit. Default is 1000.
		 * @param (string) $this->log_type The Log type.
		 */
		$limit = apply_filters( 'secupress.logs.logs_limit', 1000, $this->log_type );

		return secupress_minmax_range( $limit, 10, 10000 );
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
		$href = urlencode( esc_url_raw( $referer ) );
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
		$href = urlencode( esc_url_raw( $referer ) );
		$href = admin_url( 'admin-post.php?action=secupress_clear-' . $this->log_type . '-logs&_wp_http_referer=' . $href );
		return wp_nonce_url( $href, 'secupress-clear-' . $this->log_type . '-logs' );
	}


	/**
	 * Get the URL to delete Logs with a certain user ID.
	 *
	 * @since 1.0
	 *
	 * @param (int)    $id      User ID.
	 * @param (string) $referer The page referer.
	 *
	 * @return (string)
	 */
	public function delete_logs_by_user_id_url( $id, $referer ) {
		$id   = (int) $id;
		$href = urlencode( esc_url_raw( $referer ) );
		$href = admin_url( 'admin-post.php?action=secupress_delete-' . $this->log_type . '-logs-by-user_id&id=' . $id . '&_wp_http_referer=' . $href );
		return wp_nonce_url( $href, 'secupress-delete-' . $this->log_type . '-logs-by-user_id' );
	}


	/**
	 * Get the URL to delete Logs with a certain IP address.
	 *
	 * @since 1.0
	 *
	 * @param (string) $ip      IP address.
	 * @param (string) $referer The page referer.
	 *
	 * @return (string)
	 */
	public function delete_logs_by_ip_url( $ip, $referer ) {
		$ip   = urlencode( $ip );
		$href = urlencode( esc_url_raw( $referer ) );
		$href = admin_url( 'admin-post.php?action=secupress_delete-' . $this->log_type . '-logs-by-ip&ip=' . $ip . '&_wp_http_referer=' . $href );
		return wp_nonce_url( $href, 'secupress-delete-' . $this->log_type . '-logs-by-ip' );
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
		$href = urlencode( esc_url_raw( $referer ) );
		$href = admin_url( 'admin-post.php?action=secupress_delete-' . $this->log_type . '-log&log=' . $post_id . '&_wp_http_referer=' . $href );
		return wp_nonce_url( $href, 'secupress-delete-' . $this->log_type . '-log' );
	}


	/**
	 * Get the URL of the page displaying the list of a Log type.
	 *
	 * @since 1.0
	 *
	 * @param (string) $log_type The Log type.
	 *
	 * @return (string)
	 */
	public static function get_log_type_url( $log_type ) {
		$log_types = static::get_log_types();
		$page_url  = secupress_admin_url( 'logs' );
		$i         = 0;

		foreach ( $log_types as $type => $atts ) {
			if ( $type === $log_type ) {
				return $i ? add_query_arg( 'tab', $log_type, $page_url ) : $page_url;
			}
			++$i;
		}

		return $page_url;
	}


	/** Private methods ========================================================================= */

	/**
	 * Launch main hooks.
	 *
	 * @since 1.0
	 */
	protected function _init() {
		static $done = false;
		$init_now = did_action( 'init' ) || doing_action( 'init' );

		// Register the Post Type.
		if ( $init_now ) {
			$this->register_post_type();
		} else {
			add_action( 'init', array( $this, 'register_post_type' ), 1 );

			// Some Logs creation may have been delayed.
			add_action( 'init', array( $this, 'save_delayed_logs' ) );
		}

		// Filter the post slug to allow duplicates.
		add_filter( 'wp_unique_post_slug', array( $this, 'allow_log_name_duplicates' ), 10, 6 );

		if ( is_admin() ) {
			self::$all_criticities = array_merge( self::$all_criticities, $this->criticities );

			// For the page that lists Logs, "register" our Log type.
			add_filter( 'secupress.logs.log_types', array( $this, 'register_log_type' ), $this->log_type_priority );

			// Filter the query args used in `SecuPress_Logs_List_Table::prepare_items()`.
			add_filter( 'secupress.logs.logs_query_args', array( $this, 'logs_query_args_filter' ) );

			// Filter the available post statuses.
			add_filter( 'wp_count_posts', array( $this, 'count_posts_filter' ), 10, 2 );

			// Create the page that lists the Logs.
			add_action( ( is_multisite() ? 'network_' : '' ) . 'admin_menu', array( $this, 'maybe_create_page' ), 11 );

			// Download Logs list.
			add_action( 'admin_post_secupress_download-' . $this->log_type . '-logs',          array( $this, 'post_download_logs_ajax_post_cb' ) );

			// Empty Logs list.
			add_action( 'wp_ajax_secupress_clear-' . $this->log_type . '-logs',                array( $this, 'ajax_clear_logs_ajax_post_cb' ) );
			add_action( 'admin_post_secupress_clear-' . $this->log_type . '-logs',             array( $this, 'post_clear_logs_ajax_post_cb' ) );

			// Bulk delete Logs.
			add_action( 'wp_ajax_secupress_bulk_delete-' . $this->log_type . '-logs',          array( $this, 'ajax_bulk_delete_logs_ajax_post_cb' ) );
			add_action( 'admin_post_secupress_bulk_delete-' . $this->log_type . '-logs',       array( $this, 'post_bulk_delete_logs_ajax_post_cb' ) );

			// Delete Logs by user ID.
			add_action( 'wp_ajax_secupress_delete-' . $this->log_type . '-logs-by-user_id',    array( $this, 'ajax_bulk_delete_logs_by_user_id_ajax_post_cb' ) );
			add_action( 'admin_post_secupress_delete-' . $this->log_type . '-logs-by-user_id', array( $this, 'post_bulk_delete_logs_by_user_id_ajax_post_cb' ) );

			// Delete Logs by IP.
			add_action( 'wp_ajax_secupress_delete-' . $this->log_type . '-logs-by-ip',         array( $this, 'ajax_bulk_delete_logs_by_ip_ajax_post_cb' ) );
			add_action( 'admin_post_secupress_delete-' . $this->log_type . '-logs-by-ip',      array( $this, 'post_bulk_delete_logs_by_ip_ajax_post_cb' ) );

			// Delete a Log.
			add_action( 'wp_ajax_secupress_delete-' . $this->log_type . '-log',                array( $this, 'ajax_delete_log_ajax_post_cb' ) );
			add_action( 'admin_post_secupress_delete-' . $this->log_type . '-log',             array( $this, 'post_delete_log_ajax_post_cb' ) );
		}

		if ( ! $done ) {
			$done = true;

			// Register the Post Statuses.
			if ( $init_now ) {
				self::register_post_statuses();
			} else {
				add_action( 'init', array( __CLASS__, 'register_post_statuses' ), 5 );
			}
		}

		// Delayed Logs.
		$this->delayed_logs_transient_name = 'secupress_delayed_' . $this->get_log_type() . '_logs';

		// Autoload the transient.
		add_filter( 'secupress.options.load_plugins_network_options', array( $this, 'autoload_options' ) );
	}


	/**
	 * Register the Post Type.
	 * Labels can be customized with `$this->post_type_labels`.
	 *
	 * @since 1.0
	 */
	public function register_post_type() {
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
	 * @param (int)    $post_id       Post ID.
	 * @param (string) $post_status   The post status.
	 * @param (string) $post_type     Post type.
	 * @param (int)    $post_parent   Post parent ID.
	 * @param (string) $original_slug The original post slug.
	 *
	 * @return (string) The slug.
	 */
	public function allow_log_name_duplicates( $slug, $post_id, $post_status, $post_type, $post_parent, $original_slug ) {
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
	 * @param (array) $types Array of arrays with Log type as key and current class name + post type as values.
	 *
	 * @return (array)
	 */
	public function register_log_type( $types ) {
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
	public function logs_query_args_filter( $args ) {
		if ( ! empty( $args['post_type'] ) && $this->get_post_type() === $args['post_type'] ) {
			return $this->logs_query_args( $args );
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
	public function count_posts_filter( $counts, $type ) {
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
	public static function register_post_statuses() {
		$criticities = array(
			'high'   => array(
				'label'       => __( 'High', 'secupress' ),
				'label_count' => _n_noop( 'High <span class="count">(%s)</span>', 'High <span class="count">(%s)</span>', 'secupress' ),
				'public'      => false,
				'internal'    => true,
				'protected'   => true,
				'private'     => true,
			),
			'normal' => array(
				'label'       => __( 'Normal', 'secupress' ),
				'label_count' => _n_noop( 'Normal <span class="count">(%s)</span>', 'Normal <span class="count">(%s)</span>', 'secupress' ),
				'public'      => false,
				'internal'    => true,
				'protected'   => true,
				'private'     => true,
			),
			'low'    => array(
				'label'       => __( 'Low', 'secupress' ),
				'label_count' => _n_noop( 'Low <span class="count">(%s)</span>', 'Low <span class="count">(%s)</span>', 'secupress' ),
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
	public function maybe_create_page() {
		// To create the menu item and the page, we need to use the class used for the current Log type.
		$log_types = static::get_log_types();
		$log_type  = ! empty( $_GET['tab'] ) ? $_GET['tab'] : '';
		$log_type  = $log_type && isset( $log_types[ $log_type ] ) ? $log_type : key( $log_types );

		if ( $this->log_type !== $log_type ) {
			return;
		}

		// Create the menu item.
		add_submenu_page(
			SECUPRESS_PLUGIN_SLUG . '_scanners',
			_x( 'Logs', 'post type general name', 'secupress' ),
			_x( 'Logs', 'post type general name', 'secupress' ),
			secupress_get_capability(),
			SECUPRESS_PLUGIN_SLUG . '_logs',
			array( $this, 'page' )
		);

		// Initiate the page.
		add_action( 'load-' . SECUPRESS_PLUGIN_SLUG . '_page_' . SECUPRESS_PLUGIN_SLUG . '_logs', array( $this, 'logs_list_load' ) );
	}


	/**
	 * Prepare the list.
	 *
	 * @since 1.0
	 */
	public function logs_list_load() {
		$classname = static::maybe_include_list_class();
		$classname::get_instance()->prepare_list();
	}


	/**
	 * The page content.
	 *
	 * @since 1.0
	 */
	public function page() {
		$classname = static::maybe_include_list_class();
		$classname::get_instance()->display_list();
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
	protected function save_logs( $new_logs ) {
		if ( ! $new_logs ) {
			return 0;
		}

		$added   = [];
		$user_id = 0;

		if ( is_multisite() ) {
			// On multisite, create posts in the main blog.
			switch_to_blog( secupress_get_main_blog_id() );

			// A post author is needed.
			$user_id = static::get_default_super_administrator();
		}

		if ( ! $user_id ) {
			$user_id = static::get_default_administrator();
		}
		/**
		 * Filter the Logs author.
		 *
		 * @since 1.0
		 *
		 * @param (int) $user_id A user ID. That should be a user that won't be deleted anytime soon.
		 */
		$user_id = apply_filters( 'secupress.logs.author', $user_id );

		// Maybe it's too soon, we can't save logs before the 'init' hook.
		$log_now = did_action( 'init' ) || doing_action( 'init' );

		if ( ! $log_now ) {
			// We're before the 'init' hook, we will store the logs in a transient and create them later.
			$delayed_logs = secupress_get_site_transient( $this->delayed_logs_transient_name );
			$delayed_logs = is_array( $delayed_logs ) ? $delayed_logs : array();
		}

		foreach ( $new_logs as $new_log ) {
			$args = array(
				'post_type'   => $this->get_post_type(), // Post type / Action, 404.
				'post_date'   => $new_log['time'],       // Post date / Time.
				'menu_order'  => 0,                      // Menu order / Microtime.
				'post_parent' => isset( $new_log['parent'] ) ? (int) $new_log['parent'] : 0, // For HTTP logs or 0.
				'post_status' => 'normal',               // Post status / Criticity.
				'post_author' => $user_id,               // Post author: needed to create the post, we don't want the current user to create it.
			);

			// Menu order / Microtime.
			if ( ! empty( $new_log['order'] ) ) {
				if ( ! is_int( $new_log['order'] ) ) {
					// It's a microtime.
					$new_log['order'] = explode( ' ', $new_log['order'] );  // Ex: array( '0.03746700', '1452528510' ).
					$new_log['order'] = reset( $new_log['order'] );         // Ex: '0.03746700'.
					$new_log['order'] = explode( '.', $new_log['order'] );  // Ex: array( '0', '03746700' ).
					$new_log['order'] = end( $new_log['order'] );           // Ex: '03746700'.
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

			// It's too soon, we need to delay the log creation.
			if ( ! $log_now ) {
				$delayed_logs[] = array( 'args' => $args, 'meta' => $new_log );
				$added[] = true;
			}
			// Create the Log.
			elseif ( $post_id = static::insert_log( $args, $new_log ) ) {
				$added[] = $post_id;
			}
		}

		if ( $added ) {
			if ( ! $log_now ) {
				// Store the delayed logs.
				secupress_set_site_transient( $this->delayed_logs_transient_name, $delayed_logs );
			}
			else {
				// Limit the number of Logs stored in the database.
				$this->limit_logs_number();
			}
		}

		if ( is_multisite() ) {
			restore_current_blog();
		}

		return $added;
	}


	/**
	 * If some Logs have been delayed, create them now.
	 *
	 * @since 1.0
	 */
	public function save_delayed_logs() {
		$logs = secupress_get_site_transient( $this->delayed_logs_transient_name );

		if ( ! $logs || ! is_array( $logs ) ) {
			return;
		}

		delete_site_transient( $this->delayed_logs_transient_name );

		$added = 0;

		if ( is_multisite() ) {
			// On multisites, create posts in the main blog.
			switch_to_blog( secupress_get_main_blog_id() );
		}

		foreach ( $logs as $log ) {
			// Create the Log.
			if ( isset( $log['args'], $log['meta'] ) && $post_id = static::insert_log( $log['args'], $log['meta'] ) ) {
				++$added;
			}
		}

		// Limit the number of Logs stored in the database.
		if ( $added ) {
			$this->limit_logs_number();
		}

		if ( is_multisite() ) {
			restore_current_blog();
		}
	}


	/**
	 * Create a Log.
	 *
	 * @since 1.0
	 *
	 * @param (array) $args  Arguments for `wp_insert_post()`.
	 * @param (array) $meta  An array containing some post meta to add.
	 *
	 * @return (int|bool) The post ID on success. False on failure.
	 */
	protected static function insert_log( $args, $meta ) {
		// Create the Log.
		$post_id = wp_insert_post( $args );

		if ( ! $post_id ) {
			return false;
		}

		// Meta: data.
		if ( ! empty( $meta['data'] ) ) {
			update_post_meta( $post_id, 'data', secupress_compress_data( $meta['data'] ) );
		}

		// Meta: user IP.
		if ( ! empty( $meta['user_ip'] ) ) {
			update_post_meta( $post_id, 'user_ip', esc_html( $meta['user_ip'] ) );
		}

		// Meta: user ID.
		if ( ! empty( $meta['user_id'] ) ) {
			update_post_meta( $post_id, 'user_id', (int) $meta['user_id'] );
		}

		// Meta: user login.
		if ( ! empty( $meta['user_login'] ) ) {
			update_post_meta( $post_id, 'user_login', esc_html( $meta['user_login'] ) );
		}

		return $post_id;
	}


	/**
	 * Limit the number of Logs by deleting the old ones.
	 *
	 * @since 1.0
	 */
	protected function limit_logs_number() {
		$logs = $this->get_logs( array(
			'fields'         => 'ids',
			'offset'         => $this->get_logs_limit(),
			'posts_per_page' => 100000, // If -1, 'offset' won't work. Any large number does the trick.
			'order'          => 'DESC',
		) );

		if ( $logs ) {
			foreach ( $logs as $post_id ) {
				$this->delete_log( $post_id );
			}
		}
	}


	/** Admin post / Admin ajax ================================================================= */

	/**
	 * Admin post callback that allows to download the Logs of a certain type as a .txt file.
	 *
	 * @since 1.0
	 */
	public function post_download_logs_ajax_post_cb() {
		secupress_check_admin_referer( 'secupress-download-' . $this->log_type . '-logs' );
		secupress_check_user_capability();

		if ( ini_get( 'zlib.output_compression' ) ) {
			ini_set( 'zlib.output_compression', 'Off' );
		}

		secupress_time_limit( 0 );

		if ( ! headers_sent() ) {
			$filename = 'secupress-' . $this->log_type . '-logs-' . current_time( 'Y-m-d@H-i-s' ) . '.txt';

			ob_start();
			nocache_headers();
			header( 'Content-Type: text/plain; charset=' . get_option( 'blog_charset' ) );
			header( 'Content-Disposition: attachment; filename="' . utf8_encode( $filename ) . '"' );
			header( 'Content-Transfer-Encoding: binary' );
			header( 'Cache-Control: private, max-age=0, must-revalidate' );
			header( 'Pragma: public' );
			header( 'Connection: close' );
			ob_end_clean();
			flush();
		}

		$logs = $this->get_logs();

		if ( $logs && is_array( $logs ) ) {
			$classname  = static::maybe_include_log_class();
			$log_header = str_pad( '==%SECUPRESS-LOG%', 100, '=', STR_PAD_RIGHT ) . "\n";

			foreach ( $logs as $log ) {
				$log = new $classname( $log );

				echo $log_header;
				echo $this->get_log_header_for_file( $log ) . "\n";
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
	public function ajax_clear_logs_ajax_post_cb() {
		secupress_check_admin_referer( 'secupress-clear-' . $this->log_type . '-logs' );
		secupress_check_user_capability();

		$this->delete_logs();

		wp_send_json_success( __( 'Logs deleted.', 'secupress' ) );
	}


	/**
	 * Admin post callback that allows to delete all Logs of a certain type.
	 *
	 * @since 1.0
	 */
	public function post_clear_logs_ajax_post_cb() {
		secupress_check_admin_referer( 'secupress-clear-' . $this->log_type . '-logs' );
		secupress_check_user_capability();

		$this->delete_logs();

		secupress_add_settings_error( 'general', 'logs_cleared', __( 'Logs deleted.', 'secupress' ), 'updated' );
		set_transient( 'settings_errors', secupress_get_settings_errors(), 30 );

		$goback = add_query_arg( 'settings-updated', 'true',  wp_get_referer() );
		wp_redirect( esc_url_raw( $goback ) );
		die();
	}


	/**
	 * Ajax callback that allows to delete several Logs of a certain type.
	 *
	 * @since 1.0
	 */
	public function ajax_bulk_delete_logs_ajax_post_cb() {
		secupress_check_admin_referer( 'secupress-bulk-' . $this->log_type . '-log' );
		secupress_check_user_capability();

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
	public function post_bulk_delete_logs_ajax_post_cb() {
		secupress_check_admin_referer( 'secupress-bulk-' . $this->log_type . '-logs' );
		secupress_check_user_capability();

		if ( empty( $_GET['post'] ) || ! is_array( $_GET['post'] ) ) {
			$deleted = 0;
		} else {
			$deleted = $this->delete_logs( $_GET['post'] );
		}

		secupress_add_settings_error( 'general', 'logs_bulk_deleted', sprintf( _n( '%s log permanently deleted.', '%s logs permanently deleted.', $deleted, 'secupress' ), number_format_i18n( $deleted ) ), 'updated' );
		set_transient( 'settings_errors', secupress_get_settings_errors(), 30 );

		$goback = add_query_arg( 'settings-updated', 'true',  wp_get_referer() );
		wp_redirect( esc_url_raw( $goback ) );
		die();
	}


	/**
	 * Ajax callback that allows to delete several Logs of a certain type and with a certain user ID.
	 *
	 * @since 1.0
	 */
	public function ajax_bulk_delete_logs_by_user_id_ajax_post_cb() {
		secupress_check_admin_referer( 'secupress-delete-' . $this->log_type . '-logs-by-user_id' );
		secupress_check_user_capability();

		if ( ! isset( $_GET['id'] ) ) {
			wp_send_json_error( sprintf( _n( '%s Log deleted.', '%s Logs deleted.', 0, 'secupress' ), 0 ) );
		}

		$posts   = $this->get_logs_from_user_id( $_GET['id'], true );
		$deleted = $this->delete_logs( $posts );

		wp_send_json_success( sprintf( _n( '%s log permanently deleted.', '%s logs permanently deleted.', $deleted, 'secupress' ), number_format_i18n( $deleted ) ) );
	}


	/**
	 * Admin post callback that allows to delete several Logs of a certain type and with a certain user ID.
	 *
	 * @since 1.0
	 */
	public function post_bulk_delete_logs_by_user_id_ajax_post_cb() {
		secupress_check_admin_referer( 'secupress-delete-' . $this->log_type . '-logs-by-user_id' );
		secupress_check_user_capability();

		if ( ! isset( $_GET['id'] ) ) {
			$deleted = 0;
		} else {
			$posts   = $this->get_logs_from_user_id( $_GET['id'], true );
			$deleted = $this->delete_logs( $posts );
		}

		secupress_add_settings_error( 'general', 'logs_bulk_deleted', sprintf( _n( '%s log permanently deleted.', '%s logs permanently deleted.', $deleted, 'secupress' ), number_format_i18n( $deleted ) ), 'updated' );
		set_transient( 'settings_errors', secupress_get_settings_errors(), 30 );

		$goback = add_query_arg( 'settings-updated', 'true',  wp_get_referer() );
		wp_redirect( esc_url_raw( $goback ) );
		die();
	}


	/**
	 * Ajax callback that allows to delete several Logs of a certain type and with a certain IP.
	 *
	 * @since 1.0
	 */
	public function ajax_bulk_delete_logs_by_ip_ajax_post_cb() {
		secupress_check_admin_referer( 'secupress-delete-' . $this->log_type . '-logs-by-ip' );
		secupress_check_user_capability();

		if ( empty( $_GET['ip'] ) ) {
			wp_send_json_error( sprintf( _n( '%s Log deleted.', '%s Logs deleted.', 0, 'secupress' ), 0 ) );
		}

		$ip = urldecode( $_GET['ip'] );

		if ( ! secupress_ip_is_valid( $ip ) ) {
			wp_send_json_error( sprintf( _n( '%s Log deleted.', '%s Logs deleted.', 0, 'secupress' ), 0 ) );
		}

		$posts   = $this->get_logs_from_ip( $ip, true );
		$deleted = $this->delete_logs( $posts );

		wp_send_json_success( sprintf( _n( '%s log permanently deleted.', '%s logs permanently deleted.', $deleted, 'secupress' ), number_format_i18n( $deleted ) ) );
	}


	/**
	 * Admin post callback that allows to delete several Logs of a certain type and with a certain IP.
	 *
	 * @since 1.0
	 */
	public function post_bulk_delete_logs_by_ip_ajax_post_cb() {
		secupress_check_admin_referer( 'secupress-delete-' . $this->log_type . '-logs-by-ip' );
		secupress_check_user_capability();

		if ( empty( $_GET['ip'] ) ) {
			$deleted = 0;
		} else {
			$ip = urldecode( $_GET['ip'] );

			if ( ! secupress_ip_is_valid( $ip ) ) {
				$deleted = 0;
			} else {
				$posts   = $this->get_logs_from_ip( $ip, true );
				$deleted = $this->delete_logs( $posts );
			}
		}

		secupress_add_settings_error( 'general', 'logs_bulk_deleted', sprintf( _n( '%s log permanently deleted.', '%s logs permanently deleted.', $deleted, 'secupress' ), number_format_i18n( $deleted ) ), 'updated' );
		set_transient( 'settings_errors', secupress_get_settings_errors(), 30 );

		$goback = add_query_arg( 'settings-updated', 'true',  wp_get_referer() );
		wp_redirect( esc_url_raw( $goback ) );
		die();
	}


	/**
	 * Ajax callback that allows to delete a Log.
	 *
	 * @since 1.0
	 */
	public function ajax_delete_log_ajax_post_cb() {
		secupress_check_admin_referer( 'secupress-delete-' . $this->log_type . '-log' );
		secupress_check_user_capability();

		if ( empty( $_GET['log'] ) ) {
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
	public function post_delete_log_ajax_post_cb() {
		secupress_check_admin_referer( 'secupress-delete-' . $this->log_type . '-log' );
		secupress_check_user_capability();

		if ( empty( $_GET['log'] ) ) {
			secupress_admin_die();
		}

		if ( ! $this->delete_log( $_GET['log'] ) ) {
			secupress_admin_die();
		}

		secupress_add_settings_error( 'general', 'log_deleted', __( 'Log permanently deleted.', 'secupress' ), 'updated' );
		set_transient( 'settings_errors', secupress_get_settings_errors(), 30 );

		$goback = add_query_arg( 'settings-updated', 'true',  wp_get_referer() );
		wp_redirect( esc_url_raw( $goback ) );
		die();
	}


	/** Various ================================================================================= */

	/**
	 * Add the transient we use to store the delayed logs to be autoloaded on multisite.
	 *
	 * @since 1.0
	 *
	 * @param (array) $option_names An array of network option names.
	 *
	 * @return (array)
	 */
	public function autoload_options( $option_names ) {
		$option_names[] = '_site_transient_' . $this->delayed_logs_transient_name;
		return $option_names;
	}


	/** Tools =================================================================================== */

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
	public static function get_log_types() {
		/**
		 * Filter the Log types available. All Log types must be registered here.
		 *
		 * @since 1.0
		 *
		 * @see `$this->register_log_type()`
		 *
		 * @param (array) An array of arrays with the Log type as key and containing the post type and the name of the "logs class" as values.
		 */
		return apply_filters( 'secupress.logs.log_types', array() );
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
	public function logs_query_args( $args = array() ) {
		return array_merge( array(
			'post_type'      => $this->get_post_type(),
			'post_status'    => $this->criticities,
			'posts_per_page' => -1,
			'orderby'        => 'date menu_order',
			'order'          => 'DESC',
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
	public static function set_log_time_and_user( $log = array() ) {
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
	 * Get the default administrator.
	 *
	 * @since 1.0
	 *
	 * @return (int) A user ID.
	 */
	protected static function get_default_administrator() {
		$user_ids = get_users( array(
			'blog_id'     => secupress_get_main_blog_id(),
			'role'        => 'administrator',
			'number'      => 1,
			'orderby'     => 'ID',
			'fields'      => 'ID',
			'count_total' => false,
		) );

		return (int) reset( $user_ids );
	}


	/**
	 * Get the default super-administrator.
	 *
	 * @since 1.0
	 *
	 * @return (int) A user ID.
	 */
	protected static function get_default_super_administrator() {
		global $wpdb;

		$super_admins = get_super_admins();

		if ( ! $super_admins || ! is_array( $super_admins ) ) {
			return 0;
		}

		$super_admins = implode( "','", esc_sql( $super_admins ) );
		$user_ids     = $wpdb->get_col( "SELECT ID FROM $wpdb->users WHERE user_login IN ('$super_admins') ORDER BY ID ASC" ); // WPCS: unprepared SQL ok.

		if ( ! $user_ids ) {
			return 0;
		}

		$administrators = get_users( array(
			'blog_id'     => secupress_get_main_blog_id(),
			'role'        => 'administrator',
			'number'      => 100,
			'orderby'     => 'ID',
			'fields'      => 'ID',
			'count_total' => false,
		) );
		$user_ids = array_intersect( $user_ids, $administrators );

		return $user_ids ? (int) reset( $user_ids ) : 0;
	}


	/**
	 * Get the header content used in the `.txt` file that the user can download.
	 *
	 * @since 1.0
	 *
	 * @param (object) $log `SecuPress_Log` object.
	 *
	 * @return (string) The header content.
	 */
	public function get_log_header_for_file( $log ) {
		$out = '[' . $log->get_time() . ' | ';

		if ( count( $this->criticities ) > 1 ) {
			$out .= $log->get_criticity() . ' | ';
		}

		$user      = $log->get_user( true );
		$user_data = get_userdata( $user->user_id );

		if ( $user_data && $user_data->data->user_login !== $user->user_login ) {
			$user->user_login .= ' (' . esc_html( $user_data->data->user_login ) . ')';
		}

		if ( $user->user_id ) {
			$infos = array(
				'user_ip'    => __( 'IP', 'secupress' ),
				'user_id'    => __( 'ID', 'secupress' ),
				'user_login' => __( 'Login', 'secupress' ),
			);
			foreach ( $infos as $class => $label ) {
				$infos[ $class ] = sprintf( __( '%s:', 'secupress' ) . ' %s', $label, $user->$class );
			}
			$out .= html_entity_decode( implode( ' ', $infos ) );
		} else {
			$out .= html_entity_decode( sprintf( __( '%s:', 'secupress' ) . ' %s', __( 'IP', 'secupress' ), $user->user_ip ) );
		}

		$out .= ']';
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
	public static function maybe_include_log_class() {
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
	private static function maybe_include_list_class() {
		if ( ! class_exists( 'SecuPress_Logs_List' ) ) {
			secupress_require_class( 'Logs', 'List' );
		}

		return 'SecuPress_Logs_List';
	}
}
