<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * Render a plugin card.
 * @since 2.0
 * @author Julio Potier
 * @return (string) The plugin card
 * @param (object) $plugin The plugin informations from wp.org
 **/
function secupress_render_plugin_card( $plugin ) {
	// Quick sanity check.
	if ( ! is_object( $plugin ) ) {
		return false;
	}
	// Add thickbox for "More Details" link.
	wp_enqueue_script( 'thickbox' );
	add_thickbox();
	// Plugin Homepage.
	$plugin_url = $plugin->homepage;
	if ( ! $plugin_url ) {
		$plugin_url = 'https://wordpress.org/plugins/' . esc_attr( $plugin->slug ) . '/';
	}
	// Icon SRC.
	$orders = array( 'svg' , '2x', '1x', 'default' );
	foreach ( $orders as $order ) {
		if ( isset( $plugin->icons[ $order ] ) ) {
			$img_src = $plugin->icons[ $order ];
			break;
		}
	}
	// Timestamp.
	$last_updated_timestamp = strtotime( $plugin->last_updated );
	// Active Installs.
	if ( $plugin->active_installs >= 10000000 ) {
		$active_installs_text = _x( '10+ Million', 'Active plugin installations', 'secupress' );
	} elseif ( $plugin->active_installs >= 1000000 ) {
		$active_installs_text = _x( '1+ Million', 'Active plugin installations', 'secupress' );
	} else {
		$active_installs_text = number_format_i18n( $plugin->active_installs ) . '+';
	}
	// Action button.
	if ( current_user_can( 'install_plugins' ) || current_user_can( 'update_plugins' ) ) {
		$status = install_plugin_install_status( $plugin );

		switch ( $status['status'] ) {
			case 'install':
				if ( $status['url'] ) {
					/* translators: 1: Plugin name and version. */
					$action_link = '<a class="install-now button" data-slug="' . esc_attr( $plugin->slug ) . '" href="' . esc_url( $status['url'] ) . '" aria-label="' . esc_attr( sprintf( __( 'Install %s now', 'secupress' ), $plugin->name ) ) . '" data-name="' . esc_attr( $plugin->name ) . '">' . __( 'Install Now', 'secupress' ) . '</a>';
				}
				break;

			case 'update_available':
				if ( $status['url'] ) {
					/* translators: 1: Plugin name and version */
					$action_link = '<a class="update-now button aria-button-if-js" data-plugin="' . esc_attr( $status['file'] ) . '" data-slug="' . esc_attr( $plugin->slug ) . '" href="' . esc_url( $status['url'] ) . '" aria-label="' . esc_attr( sprintf( __( 'Update %s now', 'secupress' ), $plugin->name ) ) . '" data-name="' . esc_attr( $plugin->name ) . '">' . __( 'Update Now', 'secupress' ) . '</a>';
				}
				break;

			case 'latest_installed':
			case 'newer_installed':
				if ( is_plugin_active( $status['file'] ) ) {
					$action_link = '<button type="button" class="button button-disabled" disabled="disabled">' . _x( 'Active', 'plugin', 'secupress' ) . '</button>';
				} elseif ( current_user_can( 'activate_plugin', $status['file'] ) ) {
					$button_text  = __( 'Activate', 'secupress' );
					/* translators: %s: Plugin name */
					$button_label = _x( 'Activate %s', 'plugin', 'secupress' );
					$activate_url = add_query_arg( array(
						'_wpnonce'    => wp_create_nonce( 'activate-plugin_' . $status['file'] ),
						'action'      => 'activate',
						'plugin'      => $status['file'],
					), network_admin_url( 'plugins.php' ) );

					if ( is_network_admin() ) {
						$button_text  = __( 'Network Activate', 'secupress' );
						/* translators: %s: Plugin name */
						$button_label = _x( 'Network Activate %s', 'plugin', 'secupress' );
						$activate_url = add_query_arg( array( 'networkwide' => 1 ), $activate_url );
					}

					$action_link = sprintf(
						'<a href="%1$s" class="button activate-now" aria-label="%2$s">%3$s</a>',
						esc_url( $activate_url ),
						esc_attr( sprintf( $button_label, $plugin->name ) ),
						$button_text
					);
				} else {
					$action_link = '<button type="button" class="button button-disabled" disabled="disabled">' . _x( 'Installed', 'plugin', 'secupress' ) . '</button>';
				}
				break;
		}
	}
	$details_link = 'plugin-install.php?tab=plugin-information&amp;plugin=' . $plugin->slug . '&amp;TB_iframe=true&amp;width=600&amp;height=550';
	ob_start();
	?>
	<div class="wp-list-table widefat plugin-card plugin-card-<?php echo sanitize_html_class( $plugin->slug ); ?>">
		<div class="plugin-card-top">
			<div class="name column-name">
				<h3>
					<a href="<?php echo esc_url( $plugin_url ); ?>" target="_blank">
					<?php
					echo esc_html( $plugin->name );

					echo ' <img class="plugin-icon" src="' . $img_src . '" />';
					?>
					</a>
				</h3>
			</div>
			<div class="action-links">
				<ul class="plugin-action-buttons">
					<li>
						<?php echo $action_link; ?>
					</li>
					<li>
						<a href="<?php echo esc_url( $details_link ); ?>" class="thickbox open-plugin-details-modal" aria-label="<?php echo esc_attr( sprintf( __( 'More information about %s', 'secupress' ), $plugin->name ) ); ?>" data-title="<?php echo esc_attr( $plugin->name ); ?>"><?php _e( 'More Details', 'secupress' ); ?></a>
					</li>
				</ul>
			</div>
			<div class="desc plugin-description">
				<p>
					<?php echo wp_kses_post( $plugin->short_description ); ?>
				</p>
				<p class="authors">
					<cite><?php sprintf( __( 'By %s', 'secupress' ), wp_kses_post( $plugin->author ) ); ?></cite>
				</p>
			</div>
		</div>
		<div class="plugin-card-bottom">
			<div class="vers column-rating">
				<?php wp_star_rating( array( 'rating' => $plugin->rating, 'type' => 'percent', 'number' => $plugin->num_ratings ) ); ?>
				<span class="num-ratings" aria-hidden="true">(<?php echo number_format_i18n( $plugin->num_ratings ); ?>)</span>
			</div>
			<div class="column-updated">
				<strong><?php _e( 'Last Updated:', 'secupress' ); ?></strong> <?php printf( __( '%s ago', 'secupress' ), human_time_diff( $last_updated_timestamp ) ); ?>
			</div>
			<div class="column-downloaded">
				<?php
				printf( __( '%s Active Installations', 'secupress' ), $active_installs_text );
				?>
			</div>
			<?php
			if ( ! empty( $plugin->tested ) ) {
				$compat_class = version_compare( $GLOBALS['wp_version'], $plugin->tested ) <= 0 ? 'compatible' : 'incompatible';
			?>
			<div class="column-compatibility">
				<span class="compatibility-<?php echo $compat_class; ?>"><strong><?php _e( 'Compatible up to:', 'secupress' ); ?></strong> <?php echo esc_html( $plugin->tested ); ?></span>
			</div>
			<?php
			}
			?>
		</div>

	</div>
	<?php
	return ob_get_clean();
}
