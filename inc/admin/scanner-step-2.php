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

					<p class="secupress-item-status">
						<span class="secupress-label">Good</span>
					</p>

					<p class="secupress-item-title">Check if your login page is protected by double authentication or something like that (may be a custom script).</p>

					<p class="secupress-row-actions">
						<!--
							Things changed:
							* data-trigger added
							* data-target instead of data-test
							* data-target === .secupress-item-details' ID
						-->
						<button data-trigger="slidetoggle" data-target="details-[_ITEM_SLUG_]" class="secupress-details link-like hide-if-no-js" type="button">
							<span aria-hidden="true" class="icon">
								<i class="icon-info-disk"></i>
							</span>
							<span class="text">Learn more</span>
						</button>
					</p>
				</div>

				<div class="secupress-item-details hide-if-js" id="details-[_ITEM_SLUG_]">
					<div class="secupress-flex">
						<span class="secupress-details-icon">
							<i class="icon-i" aria-hidden="true"></i>
						</span>
						<p class="details-content">The login vector is often use in web attacks, every hour, your website is targeted by random bots whom try to log in your site. Adding another layer of login can improve the security.</p>
						<span class="secupress-placeholder"></span>
					</div>
				</div>

			</div><!-- .secupress-item-all -->

			<div class="secupress-item-all secupress-item-Easy_Login type-all status-all type-wordpress status-warning not-fixable no-fix-status alternate-1" id="Easy_Login">

				<div class="secupress-flex">

					<p class="secupress-item-status">
						<span class="secupress-label">Warning</span>
					</p>

					<p class="secupress-item-title">Check if your login page is protected by double authentication or something like that (may be a custom script).</p>

					<p class="secupress-row-actions">
						<!--
							Things changed:
							* data-trigger added
							* data-target instead of data-test
							* data-target === .secupress-item-details' ID
						-->
						<button data-trigger="slidetoggle" data-target="details-Easy_Login" class="secupress-details link-like hide-if-no-js" type="button">
							<span aria-hidden="true" class="icon">
								<i class="icon-info-disk"></i>
							</span>
							<span class="text">Learn more</span>
						</button>
					</p>
				</div><!-- .secupress-flex -->

				<div class="secupress-item-details hide-if-js" id="details-Easy_Login">
					<div class="secupress-flex">
						<span class="secupress-details-icon">
							<i class="icon-i" aria-hidden="true"></i>
						</span>
						<p class="details-content">The login vector is often use in web attacks, every hour, your website is targeted by random bots whom try to log in your site. Adding another layer of login can improve the security.</p>
						<span class="secupress-placeholder"></span>
					</div>
				</div>

			</div><!-- .secupress-item-all -->

			<div class="secupress-item-all secupress-item-Easy_Login type-all status-all type-wordpress status-bad not-fixable no-fix-status alternate-1" id="Easy_Login">

				<div class="secupress-flex">

					<p class="secupress-item-status">
						<span class="secupress-label">Bad</span>
					</p>

					<p class="secupress-item-title">Check if your login page is protected by double authentication or something like that (may be a custom script).</p>

					<p class="secupress-row-actions">
						<!--
							Things changed:
							* data-trigger added
							* data-target instead of data-test
							* data-target === .secupress-item-details' ID
						-->
						<button data-trigger="slidetoggle" data-target="details-Easy_Login" class="secupress-details link-like hide-if-no-js" type="button">
							<span aria-hidden="true" class="icon">
								<i class="icon-info-disk"></i>
							</span>
							<span class="text">Learn more</span>
						</button>
					</p>
				</div><!-- .secupress-flex -->

				<div class="secupress-item-details hide-if-js" id="details-Easy_Login">
					<div class="secupress-flex">
						<span class="secupress-details-icon">
							<i class="icon-i" aria-hidden="true"></i>
						</span>
						<p class="details-content">The login vector is often use in web attacks, every hour, your website is targeted by random bots whom try to log in your site. Adding another layer of login can improve the security.</p>
						<span class="secupress-placeholder"></span>
					</div>
				</div>

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