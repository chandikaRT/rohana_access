{
    'name': 'Rohana Access Rights',
    'version': '17.0.2.0.0',
    'summary': 'Jinasena access groups — Rohana (Sales read-only) + Jinasena_Invoicing',
    'description': """
        Rohana group:
        - Read-only access to Sales Orders and related models
        - Read-only access to Inventory Products
        - Restricted home screen (Sales + Inventory/Products menus only)
        - Inventory Overview / Operations / Configuration restricted to Inventory users

        Jinasena_Invoicing group (Accounting category, inherits Accounting/Read-only):
        - Write + Create: account.move (invoices) — create drafts, post/validate
        - Write + Create: account.move.line (invoice lines)
        - Write + Create: account.move.send (send invoice by email/PDF)
        - Write + Create: account.payment.register (register payments)
        - Read only:      sale.order + sale.order.line (view source Sales Orders)

        Designed for Odoo 17. Models/menus from optional modules are skipped if not installed.
    """,
    'author': 'Jinasena',
    'category': 'Hidden',
    'license': 'LGPL-3',
    'depends': [
        'base',
        'sale',
        'sale_management',
        'crm',
        'account',
        'stock',
        'delivery',
    ],
    'data': [
        'data/jinasena_invoicing_groups.xml',
        'security/ir.model.access.csv',
    ],
    'post_init_hook': 'post_init_hook',
    'installable': True,
    'auto_install': False,
    'application': False,
}
