<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * HTTPs Log class.
 *
 * @package SecuPress
 * @since 2.1
 */
class SecuPress_HTTP_Log extends SecuPress_Log {

	const VERSION = '1.0';

	/**
	 * The Log type.
	 *
	 * @var (string)
	 */
	protected $log_type = 'http';

	/** Instance ================================================================================ */

	/**
	 * Constructor.
	 *
	 * @since 2.1
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
			'uri' => $args->post_title,
		), $this->data );
	}


	/** Private methods ========================================================================= */

	/** Title =================================================================================== */

	/**
	 * Set the Log title.
	 *
	 * @since 2.1
	 */
	protected function set_title( $post = null ) {
		if ( isset( $post->post_parent ) && $post->post_parent > 0 ) {
			$this->title = __( 'HTTP query on %s', 'secupress' ); //// GP?
		} else {
			$this->title = __( 'Main domain %s', 'secupress' );
		}

		parent::set_title( $post );
	}


	/** Message ================================================================================= */

	/**
	 * Set the Log message.
	 *
	 * @since 2.1
	 */
	protected function set_message() {
		$form_name  = 'http_log_actions';
		$log_id     = (int) $_GET['log'];
		$log_post   = get_post( $log_id );
		$meta       = get_post_meta( $log_id, '_secupress_log_http_history', true );
		$methods    = wp_list_pluck( wp_list_pluck( $meta, 'parsed_args'), 'method' );
		if ( is_wp_error( $log_post ) || SecuPress_Logs::build_post_type_name( $this->log_type ) !== get_post_type( $log_post ) ) {
			_e( 'Error, this is not a valid HTTP log', 'secupress' );
			return;
		}
		$post_title = get_the_title( $log_post );
		$parsed_url = shortcode_atts( [ 'scheme' => '', 'host' => '', 'path' => '', 'query' => '' ], wp_parse_url( $post_title ) );
		$host_name  = $parsed_url['scheme'] . '://' . $parsed_url['host'];
		$http_logs  = get_option( SECUPRESS_HTTP_LOGS );
		ob_start();
		$input_name = sprintf( 'http_log[%s]', $host_name );
		switch ( $this->url_is_local_core( untrailingslashit( $parsed_url['host'] ), $parsed_url['path'] ) ) {
			case 'core':
				echo '<div class="secupress-log-content-message secupress-notif secupress-error"><p>';
				_e( 'This is a <strong>local URL</strong>, part of <strong>WordPress Core</strong>. We do not recommend to limit anything unless you know what you are doing. Expect unexpected results when doing it.', 'secupress' );
				echo '</p></div>';
			break;
			case 'rest':
				echo '<div class="secupress-log-content-message secupress-notif secupress-error"><p>';
				_e( 'This is a <strong>REST API</strong> URL, part of <strong>WordPress Core</strong>. We do not recommend to limit anything unless you know what you are doing. Expect unexpected results when doing it.', 'secupress' );
				echo '</p></div>';
			break;
			case 'local':
				echo '<div class="secupress-log-content-message secupress-notif secupress-error"><p>';
				_e( 'This is a <strong>local URL</strong>. We do not recommend to limit anything unless you know what you are doing. Expect unexpected results when doing it.', 'secupress' );
				echo '</p></div>';
			break;
		}
		?>
		<form name="<?php echo $form_name; ?>" id="<?php echo $form_name; ?>" action="<?php echo admin_url( 'admin-post.php' ); ?>" method="post">
			<?php wp_nonce_field( $form_name . $log_id ); ?>
			<input type="hidden" name="action" value="<?php echo $form_name; ?>">
			<input type="hidden" name="log_id" value="<?php echo $log_id; ?>">
			<h2><?php _e( 'Domain Limitation', 'secupress' ); ?></h2>
			<p><code><?php echo esc_html( $host_name ); ?>/&hellip;</code></p>
			<?php
			$value = isset( $http_logs[ $host_name ]['index'] ) ? $http_logs[ $host_name ]['index'] : 1;
			printf( __( 'Limit call to %s', 'secupress' ), '<strong><span id="limitation-text">…</span></strong>' );
			?>
			<div class="secupress-slider" data-sync-id="host">
				<div class="ui-slider-handle"></div>
			</div>
			<input type="hidden" name="<?php echo $input_name; ?>[index]" id="input-host" value="<?php echo esc_attr( $value ); ?>">
			<hr>
			<?php
			if ( $log_post->post_parent > 0 ) {
				if ( ! empty( $parsed_url['path'] ) ) {
					$path_name  = $parsed_url['scheme'] . '://' . untrailingslashit( $parsed_url['host'] ) . $parsed_url['path'];
					$input_name = sprintf( 'http_log[%s]', $path_name );
					?>
					<h2><?php _e( 'Path Limitation', 'secupress' ); ?></h2>
					<p><code><?php echo esc_html( $path_name ); ?>&hellip;</code></p>
					<div>
						<?php
						$value = isset( $http_logs[ $path_name ]['index'] ) ? $http_logs[ $path_name ]['index'] : 1;
						printf( __( 'Limit call to %s', 'secupress' ), '<strong><span id="limitation-text">…</span></strong>' );
						?>
						<div class="secupress-slider" data-sync-id="path" data-sync="host">
							<div class="ui-slider-handle"></div>
						</div>
						<input type="hidden" name="<?php echo $input_name; ?>[index]" id="input-path" value="<?php echo esc_attr( $value ); ?>">
					</div>
					<hr>
					<?php
				}

				if ( ! empty( $parsed_url['query'] ) ) {
					$query_name = $parsed_url['scheme'] . '://' . untrailingslashit( $parsed_url['host'] ) . $parsed_url['path'] . '?' . $parsed_url['query'];
					$input_name = sprintf( 'http_log[%s]', $query_name );
					?>
					<h2><?php _e( 'URL Limitation (Precise)', 'secupress' ); ?></h2>
					<p><code><?php echo esc_html( $query_name ); ?></code></p>
					<div>
						<?php
						$query_name = str_replace( '&amp;', '&', $query_name );
						$value      = isset( $http_logs[ $query_name ]['index'] ) ? $http_logs[ $query_name ]['index'] : 1;
						printf( __( 'Limit call to %s', 'secupress' ), '<strong><span id="limitation-text">…</span></strong>' );
						?>
						<div class="secupress-slider" data-sync-id="query" data-sync="path">
							<div class="ui-slider-handle"></div>
						</div>
						<input type="hidden" name="<?php echo $input_name; ?>[index]" id="input-query" value="<?php echo esc_attr( $value ); ?>">
					</div>
					<?php
				} else {
					$query_name = $path_name;
				}
				$post_params = wp_list_pluck( wp_list_pluck( $meta, 'parsed_args'), 'body' );
				if ( ! empty( $post_params ) && is_array( $post_params ) && ! empty( array_filter( $post_params ) ) ) {
					$post_params = call_user_func_array( 'array_merge', $post_params );
					$post_params = array_keys( $post_params );
					$post_params = array_flip( $post_params );
				} else {
					$post_params = [];
				}

				parse_str( htmlspecialchars_decode( $parsed_url['query'] ), $get_params );
				$get_params  = is_array( $get_params ) ? $get_params : [];
				$post_params = is_array( $post_params ) ? $post_params : [];
				if ( ! empty( $get_params ) || ! empty( $post_params ) ) {
					?>
					<hr>
					<h4><?php _e( 'Ignore Parameters', 'secupress' ); ?></h4>
					<p class="description"><?php _e( 'Any value will be ignored if checked. (*) are recommended, (G) GET, (B) BODY', 'secupress' ); ?></p>
					<fieldset class="fieldname-ignore-param fieldtype-checkbox">
						<legend class="screen-reader-text"><span><?php _e( 'Ignore HTTP Parameters', 'secupress' ); ?></span></legend>
					<?php
					$input_name = 'http_log[options][ignore-param][]';
					if ( ! empty( $get_params ) ) {
						foreach ( $get_params as $key => $value ) {
							$key   = str_replace( '#038;', '', $key );
							$class = $this->is_param_recommended( $key, $path_name ) ? 'secupress-recommended' : '';
							$check = isset( $http_logs[ $host_name ]['options']['ignore-param'] ) && in_array( $key, $http_logs[ $host_name ]['options']['ignore-param'] ) ? ' checked="checked"' : '';
							printf( '<p><label><input type="checkbox" name="%1$s" value="%2$s" class="secupress-checkbox %4$s"%5$s/><span class="label-text">(G) <code>%3$s</code> <sup>*</sup></span></label></p>',
								$input_name,
								esc_attr( $key ),
								esc_html( $key ),
								$class,
								$check,
							);
						}
					}
					if ( ! empty( $post_params ) ) {
						foreach ( $post_params as $key => $value ) {
							$class = $this->is_param_recommended( $key, $path_name ) ? 'secupress-recommended' : '';
							$check = isset( $http_logs[ $host_name ]['options']['ignore-param'] ) && in_array( $key, $http_logs[ $host_name ]['options']['ignore-param'] ) ? ' checked="checked"' : '';
							printf( '<p><label><input type="checkbox" name="%1$s" value="%2$s" class="secupress-checkbox %4$s"%5$s/><span class="label-text">(B) <code>%3$s</code> <sup>*</sup></span></label></p>',
								$input_name,
								esc_attr( $key ),
								esc_html( $key ),
								$class,
								$check,
							);
						}
					}
					?>
					</fieldset>
					<?php
				}
				?>
				<hr>
				<h4><?php _e( 'Forbidden Request Methods', 'secupress' ); ?></h4>
				<p class="description"><?php _e( 'Any non-checked method or other method not listed here will be allowed. (*) are recommended', 'secupress' ); ?></p>
				<fieldset class="fieldname-method fieldtype-checkbox">
					<legend class="screen-reader-text"><span><?php _e( 'Forbid these Requests Methods', 'secupress' ); ?></span></legend>
				<?php
				$input_name = 'http_log[options][block-method][]';
				if ( isset( $http_logs[ $query_name ]['options']['block-method'] ) ) {
					$methods   = array_merge( $methods, $http_logs[ $host_name ]['options']['block-method'] );
				}
				$methods   = array_flip( array_flip( $methods ) );
				foreach ( $methods as $value ) {
					$class = ! $this->is_param_recommended( $value, 'methods' ) ? 'secupress-recommended' : '';
					$check = isset( $http_logs[ $host_name ]['options']['block-method'] ) && in_array( $value, $http_logs[ $host_name ]['options']['block-method'] ) ? ' checked="checked"' : '';
					printf( '<p><label><input type="checkbox" name="%1$s" value="%2$s" class="secupress-checkbox %4$s"%5$s/><span class="label-text"><code>%3$s</code> <sup>*</sup></span></label></p>',
						$input_name,
						esc_attr( $value ),
						esc_html( $value ),
						$class,
						$check
					);
				}
				$methods    = array_diff( [ 'GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'TRACE', 'CONNECT' ], $methods );
				if ( ! empty( $methods ) ) {
					echo '<a href="#" id="more-methods" class="hide-if-nojs">' . __( 'More Methods&hellip;', 'secupress' ) . '</a>';
					echo '<div id="more_methods" class="hide-if-js">';
					foreach ( $methods as $value ) {
						$class = ! $this->is_param_recommended( $value, 'methods' ) ? 'secupress-recommended' : '';
						printf( '<p><label><input type="checkbox" name="%1$s" value="%2$s" class="secupress-checkbox %4$s"/><span class="label-text"><code>%3$s</code> <sup>*</sup></span></label></p>', $input_name, esc_attr( $value ), esc_html( $value ), $class );
					}
					echo '</div>';
				}
				?>
				</fieldset>
				<?php
			}
			?>
			<hr>
			<button id="save_http_log" class="secupress-button secupress-button-primary secupress-button-mini">
				<span class="text">
					<?php _e( 'Save', 'secupress' ); ?>
				</span>
			</button>
			<span class="spinner secupress-inline-spinner"></span>
		</form>
		<?php
		$history = get_post_meta( $log_id, '_' . get_post_type( $log_post ) . '_history', true );
		if ( ! empty( $history ) ) {
			?>
			<hr>
			<h2><?php _e( 'Last 10 calls', 'secupress' ); ?></h2>
			<ul>
			<?php
			$current_offset = get_option( 'gmt_offset' );
			foreach ( $history as $time => $arr ) {
				$id_hash = md5( $time );
				printf( '<li><strong>%s</strong>%s<br><code>%s</code></li>', sprintf( __( '%s ago', 'secupress' ), secupress_readable_duration( time() - $time ) ), ' <a name="' . __( 'HTTP Response Details', 'secupress' ) . '" class="hide-if-nojs thickbox" href="#TB_inline?height=400&width=600&inlineId=' . $id_hash . '">' . __( 'Open Details', 'secupress' ) . '</a>', esc_html( $arr['url'] ) );
				echo '<div id="' . $id_hash . '" class="hide-if-js">';
				echo '<h4>$args</h4>';
				var_dump( $arr['parsed_args'] );
				echo '<h4>$response</h4>';
				var_dump( $arr['response'] );
				echo'</div>';
			}
			?>
			</ul>
		<?php
		}
		ob_end_flush();

		parent::set_message();
	}

	protected function url_is_local_core( $domain, $path ) {
		$local_host = wp_parse_url( home_url(), PHP_URL_HOST );
		if ( untrailingslashit( $local_host ) !== $domain ) {
			return false;
		}
		$core_paths = [ '/wp-cron.php' => 1,
						'/wp-admin/admin-post.php' => 1,
						'/wp-admin/admin-ajax.php' => 1,
					];
		if ( isset( $core_paths[ $path ] ) ) {
			return 'core';
		}
		if ( strpos( $path, '/wp-json/wp/v2/' ) === 0 ) {
			return 'rest';
		}
		return 'local';
	}

	protected function is_param_recommended( $key, $url = '0' ) {
		$checked = [];

		$checked['methods'] =
					[
						'GET'                => true,
						'POST'               => true,
						'HEAD'               => true,
						'TRACE'              => true,
						'PUT'                => true,
						'DELETE'             => true,
						'CONNECT'            => true,
					];

		$checked['https://api.wordpress.org/plugins/update-check/1.1/'] =
					[
						'plugins'            => true,
						'translations'       => true,
						'locale'             => true,
						'all'                => true,
					];

		$checked['https://api.wordpress.org/themes/update-check/1.1/'] =
					[
						'themes'             => true,
						'translations'       => true,
						'locale'             => true,
					];

		$checked['https://api.wordpress.org/core/version-check/1.7/'] =
					[
						'version'            => true,
						'php'                => true,
						'locale'             => true,
						'mysql'              => true,
						'local_package'      => true,
						'blogs'              => true,
						'users'              => true,
						'multisite_enabled'  => true,
						'initial_db_version' => true,
						'translations'       => true,
						'update_type'        => true,
						'success'            => true,
						'fs_method'          => true,
						'fs_method_forced'   => true,
						'fs_method_direct'   => true,
						'time_taken'         => true,
						'reported'           => true,
						'attempted'          => true,
					];

		$checked['https://api.wordpress.org/events/1.0/'] =
					[
						'number'             => true,
						'ip'                 => true,
						'locale'             => true,
						'timezone'           => true,
					];

		$checked['https://api.wordpress.org/translations/core/1.0/'] =
					[
						'version'            => true,
						'wp_version'         => true,
						'locale'             => true,
					];

		$checked['https://api.wordpress.org/themes/info/1.2/'] =
					[
						'request'            => true,
					];

		$checked['https://api.wordpress.org/core/browse-happy/1.1/'] =
					[
						'useragent'          => true,
					];

		$checked['https://api.wordpress.org/core/serve-happy/1.0/'] =
					[
						'php_version'        => true,
					];

		$checked['https://secupress.me/key-api/1.0/'] =
					[
						'user_email'         => true,
						'user_key'           => true,
					];

		$checked['https://secupress.me/api/plugin/vulns.php'] =
					[
						'items'              => true,
						'type'               => true,
					];

		$checked = apply_filters( 'secupress.logs.http_params', $checked, $key, $url );

		return isset( $checked[ $url ][ $key ] );
	}

}
