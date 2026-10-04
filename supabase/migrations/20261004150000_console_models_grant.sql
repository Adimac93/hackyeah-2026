-- Console chat may use every model an enabled LLM connection on the Models page
-- lists, without a catalog or grant edit per model. The gateway honours the
-- `console:*` token only for connection-claimed models; the deny list still wins.
update public.principals
set allowed_models = array_append(allowed_models, 'console:*')
where slug = 'console-chat'
  and not ('console:*' = any(allowed_models));
