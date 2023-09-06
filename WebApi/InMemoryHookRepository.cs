namespace WebApi
{
    public class InMemoryHookRepository : IHookRepository
    {
        private List<HookRegistration> _registrations = new List<HookRegistration>();
        public InMemoryHookRepository() { 
        }

        public void AddWebHook(HookRegistration registration) 
        { 
            _registrations.Add(registration);
        }

        public void Delete(string name)
        {
            _registrations.RemoveAll(r=> r.Name.Equals(name, StringComparison.InvariantCultureIgnoreCase));
        }

        public IEnumerable<HookRegistration> GetHooks()
        {
            return _registrations;
        }
    }
}
