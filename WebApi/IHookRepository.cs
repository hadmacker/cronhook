namespace WebApi
{
    public interface IHookRepository
    {
        void AddWebHook(HookRegistration registration);
        void Delete(string name);
        IEnumerable<HookRegistration> GetHooks();
    }
}
