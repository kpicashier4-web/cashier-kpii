BEGIN;

DROP INDEX IF EXISTS public.kpi_records_one_entry_per_employee_per_day;

CREATE OR REPLACE FUNCTION public.is_admin_user()
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=public
AS $$
 SELECT EXISTS (
   SELECT 1 FROM public.profiles
   WHERE id=auth.uid() AND lower(trim(coalesce(role,'')))='admin'
 );
$$;

CREATE OR REPLACE FUNCTION public.enforce_employee_daily_limit()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=public
AS $$
BEGIN
 IF NOT public.is_admin_user() THEN
   IF NEW.employee_id <> auth.uid() THEN
     RAISE EXCEPTION 'Employees can only enter their own KPI data';
   END IF;
   IF EXISTS (
     SELECT 1 FROM public.kpi_records k
     WHERE k.employee_id=NEW.employee_id
       AND k.work_date=NEW.work_date
       AND k.id<>COALESCE(NEW.id,gen_random_uuid())
   ) THEN
     RAISE EXCEPTION 'Only one KPI entry is allowed per employee per day';
   END IF;
 END IF;
 RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_employee_daily_limit ON public.kpi_records;
CREATE TRIGGER trg_employee_daily_limit
BEFORE INSERT OR UPDATE ON public.kpi_records
FOR EACH ROW EXECUTE FUNCTION public.enforce_employee_daily_limit();

ALTER TABLE public.kpi_records ENABLE ROW LEVEL SECURITY;

DO $$
DECLARE r record;
BEGIN
 FOR r IN SELECT policyname FROM pg_policies WHERE schemaname='public' AND tablename='kpi_records'
 LOOP
   EXECUTE format('DROP POLICY IF EXISTS %I ON public.kpi_records',r.policyname);
 END LOOP;
END $$;

CREATE POLICY "kpi_select_admin_or_self" ON public.kpi_records
FOR SELECT TO authenticated
USING (public.is_admin_user() OR employee_id=auth.uid());

CREATE POLICY "kpi_insert_admin_or_self" ON public.kpi_records
FOR INSERT TO authenticated
WITH CHECK (public.is_admin_user() OR employee_id=auth.uid());

CREATE POLICY "kpi_update_admin_only" ON public.kpi_records
FOR UPDATE TO authenticated
USING (public.is_admin_user()) WITH CHECK (public.is_admin_user());

CREATE POLICY "kpi_delete_admin_only" ON public.kpi_records
FOR DELETE TO authenticated
USING (public.is_admin_user());

CREATE OR REPLACE FUNCTION public.admin_clear_monthly_kpi(p_month date)
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path=public
AS $$
DECLARE deleted_count integer;
BEGIN
 IF NOT public.is_admin_user() THEN
   RAISE EXCEPTION 'Only Admin can clear monthly data';
 END IF;
 DELETE FROM public.kpi_records
 WHERE work_date>=date_trunc('month',p_month)::date
 AND work_date<(date_trunc('month',p_month)+interval '1 month')::date;
 GET DIAGNOSTICS deleted_count=ROW_COUNT;
 RETURN deleted_count;
END;
$$;

REVOKE ALL ON FUNCTION public.admin_clear_monthly_kpi(date) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.admin_clear_monthly_kpi(date) TO authenticated;

COMMIT;
