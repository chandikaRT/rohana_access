"""
post_init_hook for rohana_access module.

Creates the "Rohana" security group with:
  - Implied groups: Internal User + Sales / User: Own Documents Only
  - Read-only ACLs for all available Sale/Stock/CRM/Account-related models
  - Menu grants: Sales app (all submenus) + Inventory/Products only
  - Inventory Overview/Operations/Configuration restricted to Inventory/User

All xmlid lookups are guarded — missing menus/models are silently skipped,
so the module installs cleanly on any Odoo 17 database regardless of which
optional enterprise modules are installed.
"""
import logging

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Menus to grant Rohana group access to
# (covers: Sales app + Inventory/Products section)
# ---------------------------------------------------------------------------
ROHANA_MENU_XMLIDS = [
    # CRM / Sales pipeline
    'crm.crm_menu_sales',
    'crm.menu_crm_opportunities',
    'crm.crm_lead_menu_my_activities',
    'crm.sales_team_menu_team_pipeline',
    'crm.res_partner_menu_customer',
    'crm.crm_team_config',
    # Inventory — root app + Products section only
    'stock.menu_stock_root',
    'stock.menu_stock_inventory_control',
    'stock.menu_product_variant_config_stock',
    'stock.product_product_menu',
    # Accounting reports (sales)
    'account_reports.menu_action_account_report_sales',
    # Point of Sale (list view)
    'point_of_sale.menu_point_of_sale_list',
    'point_of_sale.menu_report_order_details',
    # Sale core
    'sale.sale_menu_root',
    'sale.sale_order_menu',
    'sale.menu_sale_quotations',
    'sale.menu_sale_order',
    'sale.report_sales_team',
    'sale.res_partner_menu',
    'sale.menu_sale_invoicing',
    'sale.menu_sale_order_invoice',
    'sale.menu_sale_order_upselling',
    'sale.product_menu_catalog',
    'sale.menu_product_template_action',
    'sale.menu_products',
    'sale.menu_product_pricelist_main',
    'sale.menu_sale_report',
    'sale.menu_reporting_sales',
    'sale.menu_reporting_salespeople',
    'sale.menu_reporting_product',
    'sale.menu_reporting_customer',
    'sale.menu_sale_config',
    'sale.menu_sale_general_settings',
    'sale.sales_team_config',
    'sale.menu_sales_config',
    'sale.menu_tag_config',
    'sale.prod_config_main',
    'sale.menu_product_attribute_action',
    'sale.menu_product_categories',
    'sale.payment_menu',
    'sale.payment_provider_menu',
    'sale.payment_method_menu',
    'sale.next_id_16',
    'sale.menu_product_uom_categ_form_action',
    'sale.sale_menu_config_activity_plan',
    # Delivery
    'delivery.sale_menu_action_delivery_carrier_form',
    # Sale CRM integration
    'sale_crm.sale_order_menu_quotations_crm',
    # Loyalty / promotions
    'sale_loyalty.menu_discount_loyalty_type_config',
    'sale_loyalty.menu_gift_ewallet_type_config',
    # Sale management (order templates)
    'sale_management.sale_order_template_menu',
    # Optional — present only if those modules are installed
    'website_sale.menu_report_sales',
    'sale_planning.sale_planning_menu_schedule_by_sale_order',
    # Custom module menu — skipped if not installed
    'jinasena_helpdesk_repair.menu_repair_sales_order_list',
]

# ---------------------------------------------------------------------------
# Inventory menus that should be restricted to Inventory/User only
# (were previously unrestricted / visible to all internal users)
# ---------------------------------------------------------------------------
INVENTORY_RESTRICTED_MENU_XMLIDS = [
    'stock.stock_picking_type_menu',    # Overview
    'stock.menu_stock_warehouse_mgmt',  # Operations
    'stock.menu_stock_config_settings', # Configuration
]

# ---------------------------------------------------------------------------
# Read-only ACL definitions: (access_name, model_technical_name)
# Models from optional modules are silently skipped if not installed.
# ---------------------------------------------------------------------------
ROHANA_ACLS = [
    # account
    ('access_account_account_rohana_read',                  'account.account'),
    ('access_account_account_tag_rohana_read',              'account.account.tag'),
    ('access_account_analytic_account_rohana_read',         'account.analytic.account'),
    ('access_account_journal_rohana_read',                  'account.journal'),
    ('access_account_move_rohana_read',                     'account.move'),
    ('access_account_move_line_rohana_read',                'account.move.line'),
    ('access_account_move_send_rohana_read',                'account.move.send'),
    ('access_account_partial_reconcile_rohana_read',        'account.partial.reconcile'),
    ('access_account_payment_term_rohana_read',             'account.payment.term'),
    ('access_account_tax_rohana_read',                      'account.tax'),
    ('access_account_tax_group_rohana_read',                'account.tax.group'),
    # calendar
    ('access_calendar_event_rohana_read',                   'calendar.event'),
    ('access_calendar_event_type_rohana_read',              'calendar.event.type'),
    # delivery
    ('access_choose_delivery_carrier_rohana_read',          'choose.delivery.carrier'),
    ('access_delivery_carrier_rohana_read',                 'delivery.carrier'),
    ('access_delivery_price_rule_rohana_read',              'delivery.price.rule'),
    ('access_delivery_zip_prefix_rohana_read',              'delivery.zip.prefix'),
    # crm
    ('access_crm_activity_report_rohana_read',              'crm.activity.report'),
    ('access_crm_lead_rohana_read',                         'crm.lead'),
    ('access_crm_lead_lost_rohana_read',                    'crm.lead.lost'),
    ('access_crm_lead_scoring_frequency_rohana_read',       'crm.lead.scoring.frequency'),
    ('access_crm_lead_scoring_frequency_field_rohana_read', 'crm.lead.scoring.frequency.field'),
    ('access_crm_lead2opportunity_partner_rohana_read',     'crm.lead2opportunity.partner'),
    ('access_crm_lead2opportunity_partner_mass_rohana_read','crm.lead2opportunity.partner.mass'),
    ('access_crm_lost_reason_rohana_read',                  'crm.lost.reason'),
    ('access_crm_merge_opportunity_rohana_read',            'crm.merge.opportunity'),
    ('access_crm_recurring_plan_rohana_read',               'crm.recurring.plan'),
    ('access_crm_tag_rohana_read',                          'crm.tag'),
    ('access_crm_team_rohana_read',                         'crm.team'),
    # event
    ('access_event_event_rohana_read',                      'event.event'),
    ('access_event_event_ticket_rohana_read',               'event.event.ticket'),
    ('access_event_mail_rohana_read',                       'event.mail'),
    ('access_event_mail_registration_rohana_read',          'event.mail.registration'),
    ('access_event_registration_rohana_read',               'event.registration'),
    ('access_event_stage_rohana_read',                      'event.stage'),
    ('access_event_tag_rohana_read',                        'event.tag'),
    ('access_event_tag_category_rohana_read',               'event.tag.category'),
    ('access_event_type_rohana_read',                       'event.type'),
    ('access_event_type_mail_rohana_read',                  'event.type.mail'),
    ('access_event_type_ticket_rohana_read',                'event.type.ticket'),
    # event_booth (optional)
    ('access_event_booth_rohana_read',                      'event.booth'),
    ('access_event_booth_category_rohana_read',             'event.booth.category'),
    ('access_event_type_booth_rohana_read',                 'event.type.booth'),
    # event_booth_sale (optional)
    ('access_event_booth_configurator_rohana_read',         'event.booth.configurator'),
    ('access_event_booth_registration_rohana_read',         'event.booth.registration'),
    # event_crm (optional)
    ('access_event_lead_rule_rohana_read',                  'event.lead.rule'),
    # event_sale (optional)
    ('access_event_event_configurator_rohana_read',         'event.event.configurator'),
    ('access_event_sale_report_rohana_read',                'event.sale.report'),
    ('access_registration_editor_rohana_read',              'registration.editor'),
    ('access_registration_editor_line_rohana_read',         'registration.editor.line'),
    # helpdesk (optional)
    ('access_helpdesk_team_rohana_read',                    'helpdesk.team'),
    ('access_helpdesk_ticket_type_rohana_read',             'helpdesk.ticket.type'),
    # loyalty (optional)
    ('access_loyalty_card_rohana_read',                     'loyalty.card'),
    ('access_loyalty_generate_wizard_rohana_read',          'loyalty.generate.wizard'),
    ('access_loyalty_mail_rohana_read',                     'loyalty.mail'),
    ('access_loyalty_program_rohana_read',                  'loyalty.program'),
    ('access_loyalty_reward_rohana_read',                   'loyalty.reward'),
    ('access_loyalty_rule_rohana_read',                     'loyalty.rule'),
    # mrp (optional)
    ('access_mrp_bom_rohana_read',                          'mrp.bom'),
    ('access_mrp_bom_line_rohana_read',                     'mrp.bom.line'),
    ('access_mrp_production_rohana_read',                   'mrp.production'),
    ('access_mrp_workorder_rohana_read',                    'mrp.workorder'),
    # partner_commission (optional)
    ('access_commission_plan_rohana_read',                  'commission.plan'),
    ('access_commission_rule_rohana_read',                  'commission.rule'),
    # payment (optional)
    ('access_payment_link_wizard_rohana_read',              'payment.link.wizard'),
    # product
    ('access_product_attribute_rohana_read',                'product.attribute'),
    ('access_product_attribute_custom_value_rohana_read',   'product.attribute.custom.value'),
    ('access_product_attribute_value_rohana_read',          'product.attribute.value'),
    ('access_product_category_rohana_read',                 'product.category'),
    ('access_product_packaging_rohana_read',                'product.packaging'),
    ('access_product_pricelist_rohana_read',                'product.pricelist'),
    ('access_product_product_rohana_read',                  'product.product'),
    ('access_product_supplierinfo_rohana_read',             'product.supplierinfo'),
    ('access_product_template_rohana_read',                 'product.template'),
    ('access_product_template_attribute_line_rohana_read',  'product.template.attribute.line'),
    ('access_product_template_attribute_value_rohana_read', 'product.template.attribute.value'),
    # res
    ('access_res_partner_rohana_read',                      'res.partner'),
    ('access_res_partner_category_rohana_read',             'res.partner.category'),
    # sale
    ('access_sale_advance_payment_inv_rohana_read',         'sale.advance.payment.inv'),
    ('access_sale_mass_cancel_orders_rohana_read',          'sale.mass.cancel.orders'),
    ('access_sale_order_rohana',                            'sale.order'),
    ('access_sale_order_cancel_rohana_read',                'sale.order.cancel'),
    ('access_sale_order_discount_rohana_read',              'sale.order.discount'),
    ('access_sale_order_line_rohana',                       'sale.order.line'),
    ('access_sale_report_rohana_read',                      'sale.report'),
    # sale_crm (optional)
    ('access_crm_quotation_partner_rohana_read',            'crm.quotation.partner'),
    # sale_loyalty (optional)
    ('access_sale_loyalty_coupon_wizard_rohana_read',       'sale.loyalty.coupon.wizard'),
    ('access_sale_loyalty_reward_wizard_rohana_read',       'sale.loyalty.reward.wizard'),
    ('access_sale_order_coupon_points_rohana_read',         'sale.order.coupon.points'),
    # sale_management (optional)
    ('access_sale_order_option_rohana_read',                'sale.order.option'),
    ('access_sale_order_template_rohana_read',              'sale.order.template'),
    ('access_sale_order_template_line_rohana_read',         'sale.order.template.line'),
    ('access_sale_order_template_option_rohana_read',       'sale.order.template.option'),
    # sale_renting (optional)
    ('access_product_pricing_rohana_read',                  'product.pricing'),
    ('access_rental_order_wizard_rohana_read',              'rental.order.wizard'),
    ('access_rental_order_wizard_line_rohana_read',         'rental.order.wizard.line'),
    ('access_sale_rental_report_rohana_read',               'sale.rental.report'),
    ('access_sale_rental_schedule_rohana_read',             'sale.rental.schedule'),
    # sale_renting_crm (optional)
    ('access_crm_lead_rental_rohana_read',                  'crm.lead.rental'),
    # sale_subscription (optional)
    ('access_sale_order_close_reason_rohana_read',          'sale.order.close.reason'),
    ('access_sale_order_log_rohana_read',                   'sale.order.log'),
    ('access_sale_order_log_report_rohana_read',            'sale.order.log.report'),
    ('access_sale_subscription_close_reason_wizard_rohana_read', 'sale.subscription.close.reason.wizard'),
    ('access_sale_subscription_plan_rohana_read',           'sale.subscription.plan'),
    ('access_sale_subscription_pricing_rohana_read',        'sale.subscription.pricing'),
    ('access_sale_subscription_report_rohana_read',         'sale.subscription.report'),
    # sale_timesheet (optional)
    ('access_project_create_sale_order_rohana_read',        'project.create.sale.order'),
    ('access_project_create_sale_order_line_rohana_read',   'project.create.sale.order.line'),
    # stock
    ('access_stock_location_rohana_read',                   'stock.location'),
    ('access_stock_lot_rohana_read',                        'stock.lot'),
    ('access_stock_move_rohana_read',                       'stock.move'),
    ('access_stock_move_line_rohana_read',                  'stock.move.line'),
    ('access_stock_package_type_rohana_read',               'stock.package.type'),
    ('access_stock_picking_rohana_read',                    'stock.picking'),
    ('access_stock_quant_rohana_read',                      'stock.quant'),
    ('access_stock_rule_rohana_read',                       'stock.rule'),
    ('access_stock_warehouse_rohana_read',                  'stock.warehouse'),
    ('access_stock_warehouse_orderpoint_rohana_read',       'stock.warehouse.orderpoint'),
    # uom
    ('access_uom_category_rohana_read',                     'uom.category'),
    ('access_uom_uom_rohana_read',                          'uom.uom'),
    # website (optional)
    ('access_website_track_rohana_read',                    'website.track'),
    ('access_website_visitor_rohana_read',                  'website.visitor'),
    # website_crm_iap_reveal (optional)
    ('access_crm_reveal_rule_rohana_read',                  'crm.reveal.rule'),
    ('access_crm_reveal_view_rohana_read',                  'crm.reveal.view'),
    # website_crm_partner_assign (optional)
    ('access_crm_lead_assignation_rohana_read',             'crm.lead.assignation'),
    ('access_crm_lead_forward_to_partner_rohana_read',      'crm.lead.forward.to.partner'),
    ('access_crm_partner_report_assign_rohana_read',        'crm.partner.report.assign'),
    ('access_res_partner_grade_rohana_read',                'res.partner.grade'),
    # website_event (optional)
    ('access_event_question_rohana_read',                   'event.question'),
    ('access_event_question_answer_rohana_read',            'event.question.answer'),
    ('access_event_registration_answer_rohana_read',        'event.registration.answer'),
    ('access_website_event_menu_rohana_read',               'website.event.menu'),
    # website_event_exhibitor (optional)
    ('access_event_sponsor_rohana_read',                    'event.sponsor'),
    ('access_event_sponsor_type_rohana_read',               'event.sponsor.type'),
    # website_event_meet (optional)
    ('access_event_meeting_room_rohana_read',               'event.meeting.room'),
    # website_event_track (optional)
    ('access_event_track_rohana_read',                      'event.track'),
    ('access_event_track_location_rohana_read',             'event.track.location'),
    ('access_event_track_stage_rohana_read',                'event.track.stage'),
    ('access_event_track_tag_rohana_read',                  'event.track.tag'),
    ('access_event_track_tag_category_rohana_read',         'event.track.tag.category'),
    ('access_event_track_visitor_rohana_read',              'event.track.visitor'),
    # website_event_track_quiz (optional)
    ('access_event_quiz_rohana_read',                       'event.quiz'),
    ('access_event_quiz_answer_rohana_read',                'event.quiz.answer'),
    ('access_event_quiz_question_rohana_read',              'event.quiz.question'),
    # crm_helpdesk (optional)
    ('access_crm_lead_convert2ticket_rohana_read',          'crm.lead.convert2ticket'),
    # delivery_easypost (optional)
    ('access_easypost_service_rohana_read',                 'easypost.service'),
    # delivery_shiprocket (optional)
    ('access_shiprocket_channel_rohana_read',               'shiprocket.channel'),
    ('access_shiprocket_courier_rohana_read',               'shiprocket.courier'),
]


def post_init_hook(env):
    """
    Create the Rohana security group with all required ACLs and menu grants.
    Called automatically after the module is installed.
    """
    _logger.info('[rohana_access] Running post_init_hook ...')

    # ------------------------------------------------------------------
    # 1. Create / find the Rohana group
    # ------------------------------------------------------------------
    rohana = env['res.groups'].search([('name', '=', 'Rohana')], limit=1)
    if not rohana:
        rohana = env['res.groups'].create({'name': 'Rohana'})
        _logger.info('[rohana_access] Created Rohana group (id=%s)', rohana.id)
    else:
        _logger.info('[rohana_access] Found existing Rohana group (id=%s)', rohana.id)

    # ------------------------------------------------------------------
    # 2. Set implied groups (Rohana → Internal User + Sales Salesman)
    #    This propagates the implied groups to all Rohana members via ORM.
    # ------------------------------------------------------------------
    implied_xmlids = [
        'base.group_user',                    # User types / Internal User
        'sales_team.group_sale_salesman',     # Sales / User: Own Documents Only
    ]
    implied_groups = env['res.groups']
    for xmlid in implied_xmlids:
        g = env.ref(xmlid, raise_if_not_found=False)
        if g:
            implied_groups |= g
        else:
            _logger.warning('[rohana_access] Implied group not found: %s', xmlid)

    if implied_groups:
        rohana.write({'implied_ids': [(6, 0, implied_groups.ids)]})
        _logger.info('[rohana_access] Set implied groups: %s', implied_groups.mapped('full_name'))

    # ------------------------------------------------------------------
    # 3. Create read-only ACLs for all available models
    # ------------------------------------------------------------------
    IrModelAccess = env['ir.model.access']
    IrModel = env['ir.model']
    acl_created = 0
    acl_skipped = 0

    for access_name, model_name in ROHANA_ACLS:
        # Skip if ACL already exists for this group + name
        existing = IrModelAccess.search([
            ('name', '=', access_name),
            ('group_id', '=', rohana.id),
        ], limit=1)
        if existing:
            continue

        # Skip if model is not installed in this database
        model_rec = IrModel.search([('model', '=', model_name)], limit=1)
        if not model_rec:
            acl_skipped += 1
            continue

        IrModelAccess.create({
            'name': access_name,
            'model_id': model_rec.id,
            'group_id': rohana.id,
            'perm_read': True,
            'perm_write': False,
            'perm_create': False,
            'perm_unlink': False,
        })
        acl_created += 1

    _logger.info('[rohana_access] ACLs: %s created, %s skipped (model not installed)',
                 acl_created, acl_skipped)

    # ------------------------------------------------------------------
    # 4. Grant Rohana group access to Sales + Inventory/Products menus
    # ------------------------------------------------------------------
    IrUiMenu = env['ir.ui.menu']
    menu_granted = 0
    menu_skipped = 0

    for xmlid in ROHANA_MENU_XMLIDS:
        menu = env.ref(xmlid, raise_if_not_found=False)
        if not menu:
            menu_skipped += 1
            continue
        if rohana not in menu.groups_id:
            menu.write({'groups_id': [(4, rohana.id)]})
        menu_granted += 1

    _logger.info('[rohana_access] Menus: %s granted, %s skipped (not installed)',
                 menu_granted, menu_skipped)

    # ------------------------------------------------------------------
    # 5. Restrict Inventory Overview / Operations / Configuration
    #    to Inventory/User only (they previously had no group restriction,
    #    making them visible to all internal users)
    # ------------------------------------------------------------------
    inv_user = env.ref('stock.group_stock_user', raise_if_not_found=False)
    if inv_user:
        restricted = 0
        for xmlid in INVENTORY_RESTRICTED_MENU_XMLIDS:
            menu = env.ref(xmlid, raise_if_not_found=False)
            if menu and inv_user not in menu.groups_id:
                menu.write({'groups_id': [(4, inv_user.id)]})
                restricted += 1
        _logger.info('[rohana_access] Restricted %s Inventory menus to Inventory/User', restricted)
    else:
        _logger.warning('[rohana_access] stock.group_stock_user not found; Inventory menus not restricted')

    _logger.info('[rohana_access] post_init_hook complete. Rohana group id=%s', rohana.id)
