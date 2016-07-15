<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );
//// geof le contenu des box n'est pas celui des maquettes encore
?>
<div class="secupress-step-content-header secupress-flex secupress-flex-spaced">

	<?php
	$page_title = __( 'Checked items will be automatically fixed', 'secupress' );

	$main_button = //// geof: couleur et icone
	'<button class="secupress-button secupress-button-tertiary button-secupress-fix shadow" type="button" data-nonce="' . esc_attr( wp_create_nonce( 'secupress-update-oneclick-scan-date' ) ) . '">
		<span class="icon" aria-hidden="true">
			<i class="icon-check"></i>
		</span>
		<span class="text">' . esc_html__( 'Fix all checked issues', 'secupress' ) . '</span>
	</button>';
	?>

	<p class="secupress-step-title"><?php echo $page_title; ?></p>
	<p>
		<?php echo $main_button; ?>
	</p>
</div>

<div id="secupress-tests" class="secupress-tests">

	<div class="secupress-scans-group secupress-group-[_GROUP_SLUG_]">
		<div class="secupress-sg-header secupress-flex secupress-flex-spaced">

			<div class="secupress-sgh-name">
				<i class="icon-user-login" aria-hidden="true"></i>
				<p class="secupress-sgh-title">User &amp; Login</p>
				<p class="secupress-sgh-description">Protect you users</p>
			</div>

			<div class="secupress-sgh-actions secupress-flex">
				<label for="secupress-toggle-check" class="text">
					<span class="label-before-text">Toogle Group Check</span>
					<input type="checkbox" class="secupress-checkbox" id="secupress-toggle-check">
					<span class="label-text"></span>
				</label>
			</div>

		</div><!-- .secupress-sg-header -->

		<div id="secupress-group-content-[_GROUP_SLUG_]" class="secupress-sg-content">

			<div class="secupress-item-all secupress-item-[_ITEM_SLUG_] type-all status-all type-wordpress status-good not-fixable no-fix-status" id="[_ITEM_SLUG_]">
				<div class="secupress-flex">

					<p class="secupress-item-status secupress-status-mini">
						<span class="secupress-dot-bad"></span>
					</p>

					<p class="secupress-item-title">Check if your login page is protected by double authentication or something like that (may be a custom script).</p>

					<p class="secupress-row-actions">
						<input type="checkbox" name="" id="secupress-item-[_ITEM_SLUG_]" class="secupress-checkbox">
						<label for="secupress-item-[_ITEM_SLUG_]" class="label-text">
							<span class="screen-reader-text"><?php esc_html_e( 'Auto-fix this item', 'secupress' ); ?></span>
						</label>
					</p>
				</div>

			</div><!-- .secupress-item-all -->

			<!--

			Difference with others:

			* secupress-only-pro in that parent div
			* .secupress-row-actions element is filled with "is_pro" text instead of checkbox

			-->
			<div class="secupress-item-all secupress-item-Easy_Login secupress-only-pro type-all status-all type-wordpress status-warning not-fixable no-fix-status alternate-1" id="Easy_Login">

				<div class="secupress-flex">

					<p class="secupress-item-status secupress-status-mini">
						<span class="secupress-dot-bad"></span>
					</p>

					<p class="secupress-item-title">Check if your login page is protected by double authentication or something like that (may be a custom script).</p>

					<p class="secupress-row-actions">
						<span class="secupress-get-pro-version">
							<?php printf( __( 'Available in <a href="%s">Pro Version</a>', 'secupress' ), esc_url( secupress_admin_url( 'get_pro' ) ) ); ?>
						</span>
					</p>
				</div><!-- .secupress-flex -->

			</div><!-- .secupress-item-all -->

			<div class="secupress-item-all secupress-item-Easy_Login type-all status-all type-wordpress status-bad not-fixable no-fix-status alternate-1" id="Easy_Login">

				<div class="secupress-flex">

					<p class="secupress-item-status secupress-status-mini">
						<span class="secupress-dot-bad"></span>
					</p>

					<p class="secupress-item-title">Check if your login page is protected by double authentication or something like that (may be a custom script).</p>

					<p class="secupress-row-actions">
						<input type="checkbox" name="" id="secupress-item-[_ITEM_SLUG_]" class="secupress-checkbox">
						<label for="secupress-item-[_ITEM_SLUG_]" class="label-text">
							<span class="screen-reader-text"><?php esc_html_e( 'Auto-fix this item', 'secupress' ); ?></span>
						</label>
					</p>
				</div><!-- .secupress-flex -->

			</div><!-- .secupress-item-all -->
		</div><!-- .secupress-sg-content -->
	</div><!-- .secupress-scans-group -->
</div><!-- .secupress-tests -->

<div class="secupress-step-content-footer secupress-flex secupress-flex-top secupress-flex-spaced">
	<span><?php //flex col placeholder ?></span>
	<p>
		<?php echo $main_button; ?>
	</p>
</div>