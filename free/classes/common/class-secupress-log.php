<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );


/**
 * General Log class.
 *
 * @package SecuPress
 * @since 1.0
 */
class SecuPress_Log {

	const VERSION = '1.0';

	/**
	 * A DATETIME formated date.
	 *
	 * @var (string)
	 */
	protected $time = '';

	/**
	 * Part of the result of `microtime()`.
	 * Ex: `0.03746700 1452528510` => `3746700`.
	 *
	 * @var (int)
	 */
	protected $order = 0;

	/**
	 * The Log type: option, network_option, filter, action, err404. ONLY USE `[a-z0-9_]` CHARACTERS, NO `-`!
	 *
	 * @var (string)
	 */
	protected $type = '';

	/**
	 * The Log sub-type: used only with option and network_option, it can be "add" or "update".
	 *
	 * @var (string)
	 */
	protected $subtype = '';

	/**
	 * An identifier: option name, hook name...
	 *
	 * @var (string)
	 */
	protected $target = '';

	/**
	 * User IP address at the time.
	 *
	 * @var (string)
	 */
	protected $user_ip = '';

	/**
	 * User ID.
	 *
	 * @var (int)
	 */
	protected $user_id = 0;

	/**
	 * User login at the time.
	 *
	 * @var (string)
	 */
	protected $user_login = '';

	/**
	 * The Log criticity.
	 *
	 * @var (string)
	 */
	protected $critic = '';

	/**
	 * The Log data: basically its content will be used in `vsprintf()`.
	 *
	 * @var (array)
	 */
	protected $data = array();

	/**
	 * Tell if the data has been prepared and escaped before display.
	 *
	 * @var (bool)
	 */
	protected $data_escaped = false;

	/**
	 * The Log title.
	 *
	 * @var (string)
	 */
	protected $title = '';

	/**
	 * The Log message.
	 *
	 * @var (string)
	 */
	protected $message = '';


	/** Instance ================================================================================ */

	/**
	 * Constructor.
	 *
	 * @since 1.0
	 *
	 * @param (array|object) $args An array containing the following arguments. If a `WP_Post` is used, it is converted in an adequate array.
	 *                             - (string) $time       A DATETIME formated date.
	 *                             - (int)    $order      Part of the result of `microtime()`.
	 *                             - (string) $type       The Log type + subtype separated with a `|`.
	 *                             - (string) $target     An identifier.
	 *                             - (string) $user_ip    User IP address.
	 *                             - (int)    $user_id    User ID.
	 *                             - (string) $user_login User login.
	 *                             - (array)  $data       The Log data: basically what will be used in `vsprintf()` (log title and message).
	 */
	public function __construct( $args ) {
		if ( ! is_array( $args ) ) {
			// If it's a Post, convert it in an adequate array.
			$args = static::post_to_args( $args );
		}

		$args = array_merge( array(
			'time'       => '',
			'order'      => 0,
			'type'       => '',
			'target'     => '',
			'user_ip'    => '',
			'user_id'    => '',
			'user_login' => '',
			'data'       => array(),
		), $args );

		// Extract the subtype from the type.
		$args['type'] = static::split_subtype( $args['type'] );

		$this->time       = esc_html( $args['time'] );
		$this->order      = (int) $args['order'];
		$this->type       = esc_html( $args['type']['type'] );
		$this->subtype    = esc_html( $args['type']['subtype'] );
		$this->target     = esc_html( $args['target'] );
		$this->user_ip    = esc_html( $args['user_ip'] );
		$this->user_id    = (int) $args['user_id'];
		$this->user_login = esc_html( $args['user_login'] );

		if ( ! empty( $args['critic'] ) ) {
			// It comes from the post status of a Post.
			$this->critic = esc_html( $args['critic'] );
		} else {
			// Set the criticity, depending on other arguments.
			$this->set_criticity();
		}

		$this->data = (array) $args['data'];
	}


	/** Public methods ========================================================================== */

	/**
	 * Get the Log formated date and time.
	 *
	 * @since 1.0
	 *
	 * @param (string) $format See http://de2.php.net/manual/en/function.date.php.
	 *
	 * @return (string) The formated date.
	 */
	public function get_time( $format = false ) {
		if ( ! is_string( $format ) ) {
			$format = __( 'Y/m/d g:i:s a' );
		}

		return mysql2date( $format, $this->time, true );
	}


	/**
	 * Get the Log title.
	 *
	 * @since 1.0
	 *
	 * @return (string) A title containing some related data.
	 */
	public function get_title( $post ) {
		$this->set_title( $post );
		return $this->title;
	}


	/**
	 * Get the Log message.
	 *
	 * @since 1.0
	 *
	 * @return (string) A message containing all related data.
	 */
	public function get_message() {
		$this->set_message();

		if ( preg_match( "/^<pre>(.+\n.+)<\/pre>$/", $this->message, $matches ) ) {
			$data[ $key ] = '<code>' . substr( $matches[1], 0, 50 ) . '&hellip;</code>';
		}

		return $this->message;
	}


	/**
	 * Get the user infos.
	 *
	 * @since 1.0
	 *
	 * @param (bool)   $raw     If true, the method will return raw values in an array. If false, the method will return formated infos as a string.
	 * @param (string) $referer If the user exists and is not the current user, a link to the user's profile is provided. A referer is needed for this link.
	 * @param (array)  $filters An array of URLs used to filter the list results. Keys are `user_ip`, `user_id` and `user_login`. Values will be used in `sprintf()`.
	 *
	 * @return (object|string) An object of raw infos, or formated infos as a string.
	 */
	public function get_user( $raw = false, $referer = false, $filters = array() ) {
		if ( $raw ) {
			return (object) array(
				'user_ip'    => $this->user_ip,
				'user_id'    => $this->user_id,
				'user_login' => $this->user_login,
			);
		}

		$user_ip    = '<code>' . $this->user_ip . '</code>';
		$user_id    = $this->user_id;
		$user_login = $this->user_login;

		// Filter Logs by IP.
		if ( ! empty( $filters['user_ip'] ) ) {
			$user_ip = '<a title="' . esc_attr( sprintf( __( 'Filter logs with the IP address %s', 'secupress' ), $this->user_ip ) ) . '" href="' . esc_url( sprintf( $filters['user_ip'], urlencode( $this->user_ip ) ) ) . '" class="secupress-action-filter-ip">' . $user_ip . '</a>';
		}

		// Filter Logs by id.
		if ( $user_id && ! empty( $filters['user_id'] ) ) {
			$user_id = '<a title="' . esc_attr( sprintf( __( 'Filter logs with the user ID %d', 'secupress' ), $user_id ) ) . '" href="' . esc_url( sprintf( $filters['user_id'], $user_id ) ) . '" class="secupress-action-filter-id">' . $user_id . '</a>';
		}

		// Filter Logs by login.
		if ( $user_login && ! empty( $filters['user_login'] ) ) {
			$user_login = '<a title="' . esc_attr( sprintf( __( 'Filter logs with the user login "%s"', 'secupress' ), $user_login ) ) . '" href="' . esc_url( sprintf( $filters['user_login'], urlencode( $user_login ) ) ) . '" class="secupress-action-filter-login">' . $user_login . '</a>';
		}

		// If the user exists and is not the current user.
		if ( get_current_user_id() !== $this->user_id && $data = get_userdata( $this->user_id ) ) {

			// Login changed? Add the current one.
			if ( $data->data->user_login !== $this->user_login ) {
				$suffix = esc_html( $data->data->user_login );
			}
			// Add a link to the user's profile page.
			elseif ( $referer ) {
				$suffix = __( 'Profile', 'secupress' );
			}
			else {
				$suffix = '';
			}

			if ( $referer ) {
				$suffix = '<a class="user-profile-link" href="' . esc_url( admin_url( 'user-edit.php?user_id=' . $this->user_id . '&amp;wp_http_referer=' . urlencode( esc_url_raw( $referer ) ) ) ) . '">' . $suffix . '</a>';
			}

			if ( $suffix ) {
				$user_login .= ' (' . $suffix . ')';
			}
		}

		if ( $this->user_id ) {
			$out   = '';
			$infos = array(
				'ip'    => __( 'IP', 'secupress' ),
				'id'    => __( 'ID', 'secupress' ),
				'login' => __( 'Login', 'secupress' ),
			);
			foreach ( $infos as $class => $label ) {
				$var  = 'user_' . $class;
				$out .= sprintf( '<span class="%s"><b>%s</b> %s</span> ', $class, sprintf( __( '%s:', 'secupress' ), $label ), $$var );
			}
			return $out;
		}

		return sprintf( '<span class="%s"><b>%s</b> %s</span> ', 'ip', sprintf( __( '%s:', 'secupress' ), __( 'IP', 'secupress' ) ), $user_ip );
	}


	/**
	 * Get the Log criticity.
	 *
	 * @since 1.0
	 *
	 * @param (string) $mode Tell what format to return. Can be "text", "icon" or whatever else.
	 *
	 * @return (string) The criticity formated like this:
	 *                  - "icon": an icon with a title attribute.
	 *                  - "text": the criticity name.
	 *                  - whatever: the criticity value, could be used as a html class.
	 */
	public function get_criticity( $mode = 'text' ) {
		if ( ! $this->critic ) {
			$this->set_criticity();
		}

		if ( 'icon' === $mode ) {
			switch ( $this->critic ) {
				case 'high':
					return '<span class="secupress-icon dashicons dashicons-shield-alt criticity-high" title="' . esc_attr__( 'High priority', 'secupress' ) . '"></span>';
				case 'normal':
					return '<span class="secupress-icon dashicons dashicons-shield-alt criticity-normal" title="' . esc_attr__( 'Normal priority', 'secupress' ) . '"></span>';
				case 'low':
					return '<span class="secupress-icon dashicons dashicons-shield-alt criticity-low" title="' . esc_attr__( 'Low priority', 'secupress' ) . '"></span>';
				default:
					return '<span class="secupress-icon dashicons dashicons-shield-alt criticity-unknown" title="' . esc_attr__( 'Unknown priority', 'secupress' ) . '"></span>';
			}
		} elseif ( 'text' === $mode ) {
			switch ( $this->critic ) {
				case 'high':
					return _x( 'High', 'priority level', 'secupress' );
				case 'normal':
					return _x( 'Normal', 'priority level', 'secupress' );
				case 'low':
					return _x( 'Low', 'priority level', 'secupress' );
				default:
					return _x( 'Unknown', 'priority level', 'secupress' );
			}
		}

		return $this->critic;
	}


	/**
	 * Tell if a log exists.
	 *
	 * @since 1.0
	 *
	 * @param (int)    $id   A Log ID.
	 * @param (string) $type A Log type. If specified, the Log type will also be tested.
	 *
	 * @return (bool|int) The Log ID on success. False on failure.
	 */
	public static function log_exists( $id, $type = false ) {
		$id = (int) $id;

		if ( $id <= 0 ) {
			false;
		}

		$log = get_post( $id );

		if ( ! $log ) {
			return false;
		}

		$id = (int) $log->ID;

		if ( ! $type ) {
			return $id;
		}

		$type = SecuPress_Logs::build_post_type_name( $type );
		return $log->post_type === $type ? $id : false;
	}


	/** Private methods ========================================================================= */

	/** Data ==================================================================================== */

	/**
	 * Get the data.
	 *
	 * @since 1.0
	 *
	 * @return (array)
	 */
	public function get_data() {
		return $this->data;
	}


	/**
	 * Set the data.
	 *
	 * @since 1.0
	 *
	 * @param (array) $data The data.
	 */
	protected function set_data( $data ) {
		$this->data = $data;
	}


	/**
	 * Prepare and escape the data. This phase is mandatory before displaying it in the Logs list.
	 *
	 * @since 1.0
	 *
	 * @return (bool) True if ready to be displayed. False if not or empty.
	 */
	protected function escape_data() {
		static $color_done = false;

		if ( ! $this->data ) {
			return false;
		}

		if ( $this->data_escaped ) {
			return true;
		}

		$this->data_escaped = true;

		if ( ! $color_done ) {
			$color_done = true;

			// Make sure we have the default values, or our CSS won't work.
			if ( wp_is_ini_value_changeable( 'highlight.default' ) ) {
				ini_set( 'highlight.default', '#0000BB' );
			}
			if ( wp_is_ini_value_changeable( 'highlight.keyword' ) ) {
				ini_set( 'highlight.keyword', '#007700' );
			}
			if ( wp_is_ini_value_changeable( 'highlight.string' ) ) {
				ini_set( 'highlight.string', '#DD0000' );
			}
		}

		// Prepare and escape the data.
		foreach ( $this->data as $key => $data ) {
			if ( is_null( $data ) ) {
				$this->data[ $key ] = '<em>[null]</em>';
			} elseif ( true === $data ) {
				$this->data[ $key ] = '<em>[true]</em>';
			} elseif ( false === $data ) {
				$this->data[ $key ] = '<em>[false]</em>';
			} elseif ( '' === $data ) {
				// If changed, also change it in `SecuPress_Action_Log::set(_network)_option_title()` and `::set(_network)_option_message()`.
				$this->data[ $key ] = '<em>[' . __( 'empty string', 'secupress' ) . ']</em>';
			} else {
				if ( ! is_scalar( $data ) ) {
					$data = call_user_func( 'var_export', $data, true );
				}

				if ( substr_count( $data, "\n" ) ) {
					// Add some (uggly) colors.
					$data = highlight_string( "<?php\n$data", true );
					// Remove wrappers.
					$data = preg_replace( '@^<code>\s*<span style="color: *#000000">\s*(.*)\s*</span>\s*</code>$@', '$1', $data );
					// Remove the first `<?php`.
					if ( preg_match( '@^(<span .+>)&lt;\?php<br \/>(</span>)?@', $data, $matches ) ) {
						$replacement = ! empty( $matches[2] ) ? '' : '$1';
						$data        = preg_replace( '@^(<span .+>)&lt;\?php<br \/>(</span>)?@', $replacement, $data );
					}
					// Replace the `style` attributes by `class` attributes.
					$data = preg_replace( '@<span style="color: #([0-9A-F]+)">@', '<span class="secupress-code-color secupress-code-color-$1">', $data );
					$this->data[ $key ] = "<pre><code>$data</code></pre>";
				} elseif ( strlen( $data ) > 50 ) {
					// 50 seems to be a good limit between short and long code.
					$this->data[ $key ] = '<pre><code>' . esc_html( $data ) . '</code></pre>';
				} else {
					$this->data[ $key ] = '<code>' . esc_html( $data ) . '</code>';
				}
			}
		}

		return true;
	}


	/** Title =================================================================================== */

	/**
	 * Set the Log title.
	 *
	 * @since 1.0
	 */
	protected function set_title( $post = null ) {
		/**
		 * First, `$this->title` must be set by the method extending this one.
		 */
		if ( ! $this->escape_data() ) {
			return;
		}

		$data = $this->data;

		// Replace the `<pre>` blocks with `<code>` inline blocks.
		foreach ( $data as $key => $value ) {
			if ( preg_match( '/^<pre>(?:<code>)?(.*)(?:<\/code>)?<\/pre>$/', $value, $matches ) ) {
				$matches[1]   = explode( "\n", $matches[1] );
				$matches[1]   = reset( $matches[1] );
				$data[ $key ] = '<code>' . strip_tags( $matches[1] ) . '</code>';
			}
		}

		// Add the data to the title.
		$this->title = apply_filters( 'secupress.logs.set_title', vsprintf( $this->title, $data ), $this->title, $data, $post );
	}


	/** Message ================================================================================= */

	/**
	 * Set the Log message.
	 *
	 * @since 1.0
	 */
	protected function set_message() {
		/**
		 * First, `$this->message` must be set by the method extending this one.
		 */
		if ( $this->escape_data() ) {
			// Make sure to have enough data to print, some messages could have been changed and need new (missing) information.
			$this->data[] = '';
			$this->data[] = '';
			// Add the data to the message.
			$this->message = vsprintf( $this->message, $this->data );
		}
	}


	/** Criticity =============================================================================== */

	/**
	 * Set the Log criticity.
	 *
	 * @since 1.0
	 */
	protected function set_criticity() {
		$this->critic = 'normal';
	}


	/** Tools =================================================================================== */

	/**
	 * Convert a Post object into an array that can be used to instanciate a Log.
	 *
	 * @since 1.0
	 *
	 * @param (int|object) $post A post ID or a `WP_Post` object.
	 *
	 * @return (array)
	 */
	protected static function post_to_args( $post ) {
		$post = get_post( $post );

		if ( ! $post || ! is_a( $post, 'WP_Post' ) || ! $post->ID ) {
			return array();
		}

		$args = array(
			'time'       => $post->post_date,
			'order'      => $post->menu_order,
			'type'       => $post->post_name,
			'target'     => $post->post_title,
			'critic'     => $post->post_status,
			'user_ip'    => get_post_meta( $post->ID, 'user_ip', true ),
			'user_id'    => get_post_meta( $post->ID, 'user_id', true ),
			'user_login' => get_post_meta( $post->ID, 'user_login', true ),
			'data'       => secupress_decompress_data( get_post_meta( $post->ID, 'data', true ) ),
		);

		$args['type'] = str_replace( '-', '|', $args['type'] );

		return $args;
	}


	/**
	 * Split a type into type + sub-type.
	 * Type and sub-type are separated with a "|" caracter. Only option and network_option have a sub-type.
	 *
	 * @since 1.0
	 *
	 * @param (string) $type A Log type.
	 *
	 * @return (array) An array containing the type an (maybe) the sub-type.
	 */
	protected static function split_subtype( $type ) {
		$out = array(
			'type'    => $type,
			'subtype' => '',
		);

		if ( strpos( $type, '|' ) !== false ) {
			$type   = explode( '|', $type, 2 );
			$type[] = '';

			$out['type']    = $type[0];
			$out['subtype'] = $type[1];
		}

		return $out;
	}
}
